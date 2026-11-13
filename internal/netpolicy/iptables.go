package netpolicy

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// The iptables binaries are the interface, not netlink.
//
// The host runs iptables v1.8.11, which is the nft shim, and Docker's pinned
// "iptables" firewall backend writes through the same shim
// (design.md §4). A Go implementation speaking native nftables
// netlink would create rules in a different table: they would not interleave
// with Docker's chains and would be invisible to `iptables -C`.
const (
	ipt4 = "iptables"
	ipt6 = "ip6tables"
)

// Chains the control plane may write to.
//
// DOCKER-USER is the only one. It is jumped first from FORWARD, before
// DOCKER-FORWARD → DOCKER-CT. DOCKER, DOCKER-FORWARD, DOCKER-CT, DOCKER-BRIDGE
// and DOCKER-INTERNAL belong to the daemon, which rewrites them at will.
const (
	ChainInput      = "INPUT"
	ChainDockerUser = "DOCKER-USER"
)

// TagPrefix marks every rule this package owns.
//
// Rules are matched for deletion by their comment, never by position or by
// their bare match spec. Untagged deletion is how test/netprobe's cleanup used
// to strip the platform's live host-protection rule: an untagged
// `INPUT -i br-t-+ -j DROP` is indistinguishable from anyone else's.
const TagPrefix = "v2p"

// iptRunner executes iptables. Swapped out in tests.
type iptRunner interface {
	run(bin string, args ...string) (string, error)
}

type execRunner struct{}

func (execRunner) run(bin string, args ...string) (string, error) {

	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {

		var ee *exec.ExitError
		if errors.As(err, &ee) {

			return string(out), &iptError{bin: bin, args: args, code: ee.ExitCode(), out: strings.TrimSpace(string(out))}
		}
		return string(out), fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	return string(out), nil
}

type iptError struct {
	bin  string
	args []string
	code int
	out  string
}

func (e *iptError) Error() string {

	return fmt.Sprintf("%s %s: exit %d: %s", e.bin, strings.Join(e.args, " "), e.code, e.out)
}

// exitCode returns the process exit status of an iptables failure, or -1.
//
// `iptables -C` uses exit 1 for "rule absent", which is a normal answer rather
// than an error, so callers have to be able to tell it from a real failure.
func exitCode(err error) int {

	var ie *iptError
	if errors.As(err, &ie) {

		return ie.code
	}
	return -1
}

// Rule is one netfilter rule as this package writes it.
type Rule struct {
	Table   string // "" means filter
	Chain   string
	Spec    []string // match and target, without -t/-A/-I and without the comment
	Comment string   // the TagPrefix-prefixed tag; required
	V6      bool
}

func (r Rule) bin() string {

	if r.V6 {

		return ipt6
	}
	return ipt4
}

// args renders the rule's arguments for the given operation verb.
func (r Rule) args(verb string, pos int) []string {

	args := []string{verb, r.Chain}
	if verb == "-I" && pos > 0 {

		args = append(args, strconv.Itoa(pos))
	}
	// The comment match must precede -j, which iptables requires to be last.
	spec := r.Spec
	var target []string
	for i := 0; i+1 < len(spec); i++ {

		if spec[i] == "-j" {

			target = spec[i:]
			spec = spec[:i]
			break
		}
	}
	args = append(args, spec...)
	args = append(args, "-m", "comment", "--comment", r.Comment)
	args = append(args, target...)
	return args
}

// IsDrop reports whether the rule's target is DROP, which decides where in the
// chain it belongs: every owned accept sits above every owned deny.
func (r Rule) IsDrop() bool {

	for i, s := range r.Spec {

		if s == "-j" && i+1 < len(r.Spec) {

			return r.Spec[i+1] == "DROP"
		}
	}
	return false
}

// String renders the rule for logs and audit subject refs.
func (r Rule) String() string {

	return fmt.Sprintf("%s %s %s [%s]", r.bin(), r.Chain, strings.Join(r.Spec, " "), r.Comment)
}

// ipt wraps the iptables binaries. One type, one place rules are written
// (design §9.6).
type ipt struct {
	r iptRunner
}

func newIpt() *ipt { return &ipt{r: execRunner{}} }

// exists reports whether the rule is currently installed.
func (i *ipt) exists(r Rule) (bool, error) {

	_, err := i.r.run(r.bin(), r.args("-C", 0)...)
	if err == nil {

		return true, nil
	}
	if code := exitCode(err); code == 1 || code == 2 {

		// 1: no such rule. 2: bad argument, which for ip6tables on this host
		// means the module or chain is not present — treated as absent so the
		// insert then fails, and the caller decides whether a missing v6 chain
		// is moot or a gap (EnsurePlatformRules; design.md §9.3).
		return false, nil
	}
	return false, err
}

// insert puts the rule at pos (1-based) if it is not already present, and
// reports whether it had to be written.
func (i *ipt) insert(r Rule, pos int) (bool, error) {

	present, err := i.exists(r)
	if err != nil {

		return false, err
	}
	if present {

		return false, nil
	}
	if _, err := i.r.run(r.bin(), r.args("-I", pos)...); err != nil {

		return false, err
	}
	return true, nil
}

// remove deletes the rule if present, and reports whether it had to.
func (i *ipt) remove(r Rule) (bool, error) {

	present, err := i.exists(r)
	if err != nil || !present {

		return false, err
	}
	if _, err := i.r.run(r.bin(), r.args("-D", 0)...); err != nil {

		return false, err
	}
	return true, nil
}

// removeByComment deletes every rule in a chain carrying an exact comment, and
// returns how many went.
//
// By LINE NUMBER, not by rule spec, because the caller only knows the rule from
// a listing: a garbage-collected rule is one whose grant has lapsed, and the
// spec that produced it is no longer derivable from the current grant set.
//
// Deleting by line shifts every line below it, so this re-lists after each
// delete rather than computing offsets. The loop is bounded: an unbounded
// delete loop against a chain that is not shrinking is a hang in the reconcile
// tick, which is worse than a leftover rule.
func (i *ipt) removeByComment(chain, comment string, v6 bool) (int, error) {

	const maxDeletes = 64
	bin := ipt4
	if v6 {

		bin = ipt6
	}
	removed := 0
	for range maxDeletes {

		listed, err := i.list(chain, v6)
		if err != nil {

			return removed, err
		}
		line := 0
		for _, lr := range listed {

			if lr.Comment == comment {

				line = lr.Line
				break
			}
		}
		if line == 0 {

			return removed, nil
		}
		if _, err := i.r.run(bin, "-D", chain, strconv.Itoa(line)); err != nil {

			return removed, err
		}
		removed++
	}
	return removed, fmt.Errorf("netpolicy: %s in %s still present after %d deletes", comment, chain, maxDeletes)
}

// ListedRule is a rule as read back from the live chain.
type ListedRule struct {
	Chain   string
	Line    int
	Target  string
	Comment string
	Raw     string
	V6      bool
}

var commentRe = regexp.MustCompile(`/\* (.*?) \*/`)

// list reads a chain back with line numbers.
//
// The line number is the point: design.md §9.5 verified that the
// accept-above-denies shape is a correctness requirement, and that presence
// alone is not enough to assert it.
func (i *ipt) list(chain string, v6 bool) ([]ListedRule, error) {

	bin := ipt4
	if v6 {

		bin = ipt6
	}
	out, err := i.r.run(bin, "-L", chain, "-n", "-v", "--line-numbers")
	if err != nil {

		return nil, err
	}
	var rules []ListedRule
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {

		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "Chain ") || strings.HasPrefix(line, "num ") {

			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {

			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {

			continue
		}
		lr := ListedRule{Chain: chain, Line: n, Target: fields[3], Raw: line, V6: v6}
		if m := commentRe.FindStringSubmatch(line); m != nil {

			lr.Comment = m[1]
		}
		rules = append(rules, lr)
	}
	return rules, sc.Err()
}
