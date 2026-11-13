package pkgvalidate

import (
	"fmt"
	"strconv"
	"strings"
)

// version is a parsed major.minor.patch. PocketBase publishes plain semver with
// no pre-release suffixes, so a three-field parser is enough and avoids pulling
// a dependency in for it.
type version struct {
	major, minor, patch int
	patchAny            bool // "0.30.x"
	minorAny            bool // "0.x"
}

func parseVersion(s string) (version, error) {

	var v version
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 2 && len(parts) != 3 {

		return v, fmt.Errorf("%w: %q is not major.minor[.patch]", ErrRange, s)
	}
	nums := make([]int, 0, 3)
	for i, p := range parts {

		if p == "x" || p == "*" {

			switch i {

			case 1:
				v.minorAny = true
			case 2:
				v.patchAny = true
			default:
				return version{}, fmt.Errorf("%w: %q may not wildcard the major version", ErrRange, s)
			}
			nums = append(nums, 0)
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {

			return version{}, fmt.Errorf("%w: %q has a non-numeric component %q", ErrRange, s, p)
		}
		nums = append(nums, n)
	}
	v.major, v.minor = nums[0], nums[1]
	if len(nums) == 3 {

		v.patch = nums[2]

	} else {

		v.patchAny = true
	}
	if v.minorAny {

		v.patchAny = true
	}
	return v, nil
}

func (v version) compare(o version) int {

	switch {

	case v.major != o.major:
		return sign(v.major - o.major)
	case v.minor != o.minor:
		return sign(v.minor - o.minor)
	case v.patch != o.patch:
		return sign(v.patch - o.patch)
	default:
		return 0
	}
}

func sign(n int) int {

	switch {

	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// upperBound expands a wildcard max into the highest version it admits.
// "0.30.x" means every 0.30 patch, so the bound is 0.30.(max int).
func (v version) upperBound() version {

	out := v
	if v.minorAny {

		out.minor = 1 << 30
	}
	if v.patchAny {

		out.patch = 1 << 30
	}
	return out
}

// Compare orders two concrete runtime versions: -1, 0 or +1.
//
// Exported for the upgrade path (§12), which has to answer two questions the
// range checks cannot: is this target the same version the tenant already runs,
// and is it LOWER? A downgrade is not merely refused, it is a category error —
// runtime upgrades are one-way (INV-4) and going back is a snapshot restore.
// Wildcards are rejected here: an upgrade target is always a concrete version.
func Compare(a, b string) (int, error) {

	av, err := parseVersion(a)
	if err != nil {

		return 0, err
	}
	bv, err := parseVersion(b)
	if err != nil {

		return 0, err
	}
	if av.minorAny || av.patchAny || bv.minorAny || bv.patchAny {

		return 0, fmt.Errorf("pkgvalidate: cannot order wildcard versions %q and %q", a, b)
	}
	return av.compare(bv), nil
}

// Satisfies reports whether a runtime version falls inside [min, max].
//
// An empty bound is open: a manifest that names only a minimum is common, and
// refusing it would make the manifest harder to write than the platform needs.
func Satisfies(runtime, min, max string) (bool, error) {

	rv, err := parseVersion(runtime)
	if err != nil {

		return false, err
	}
	if min != "" {

		mv, err := parseVersion(min)
		if err != nil {

			return false, fmt.Errorf("%w (min)", err)
		}
		if rv.compare(mv) < 0 {

			return false, nil
		}
	}
	if max != "" {

		xv, err := parseVersion(max)
		if err != nil {

			return false, fmt.Errorf("%w (max)", err)
		}
		if rv.compare(xv.upperBound()) > 0 {

			return false, nil
		}
	}
	return true, nil
}

// IntersectsSupported reports whether the range admits at least one runtime the
// platform actually offers.
//
// A manifest pinning "0.19.x" parses, is internally consistent, and can never
// be scheduled. Catching that at upload is the difference between a clear error
// and a tenant wondering why every deploy is rejected.
func IntersectsSupported(min, max string, supported []string) (bool, error) {

	for _, s := range supported {

		ok, err := Satisfies(s, min, max)
		if err != nil {

			return false, err
		}
		if ok {

			return true, nil
		}
	}
	return false, nil
}

// ValidRange checks a manifest's bounds in isolation: both parse, and min is
// not above max.
func ValidRange(min, max string) error {

	var lo, hi version
	var err error
	if min != "" {

		if lo, err = parseVersion(min); err != nil {

			return fmt.Errorf("%w (min)", err)
		}
	}
	if max != "" {

		if hi, err = parseVersion(max); err != nil {

			return fmt.Errorf("%w (max)", err)
		}
	}
	if min != "" && max != "" && lo.compare(hi.upperBound()) > 0 {

		return fmt.Errorf("%w: min %s is above max %s", ErrRange, min, max)
	}
	return nil
}
