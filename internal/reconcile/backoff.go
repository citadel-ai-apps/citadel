package reconcile

import "time"

// backoffLadder is the restart schedule from design §8.3.
//
// After the last rung the reconciler stops trying and marks the instance
// failed. A hook with an infinite loop must not become a restart storm, and an
// instance that will never come up should be a visible failure rather than a
// permanent churn of container creates.
var backoffLadder = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	2 * time.Minute,
}

// MaxRestarts is the number of attempts before an instance is marked failed.
//
// One immediate attempt plus one per rung of the ladder: the ladder describes
// the waits between attempts, so four waits mean five attempts.
var MaxRestarts = len(backoffLadder) + 1

// backoffReady reports whether enough time has passed since the last restart to
// try again, and how long remains if not.
//
// A false with a zero wait means the ladder is exhausted — that is how the
// caller tells "wait longer" apart from "give up and mark failed".
//
// The count and timestamp live in the instance row, so the ladder survives a
// control-plane restart. Otherwise killing and restarting the daemon would reset
// the count and turn a permanently failing tenant back into a restart storm.
func backoffReady(attempts int, last *time.Time, now time.Time) (ready bool, wait time.Duration) {

	if attempts <= 0 || last == nil {

		return true, 0
	}
	if attempts > len(backoffLadder) {

		return false, 0
	}
	due := last.Add(backoffLadder[attempts-1])
	if now.Before(due) {

		return false, due.Sub(now)
	}
	return true, 0
}
