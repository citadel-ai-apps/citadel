package auditlog

// ChainHashV1ForTest computes a record's v1 hash over prev, so tests can
// fabricate rows the way a pre-v2 control plane wrote them.
func ChainHashV1ForTest(r Record, prev string) string {

	detail, err := encodeDetail(r.Detail)
	if err != nil {

		panic(err)
	}
	return chainHash(r.Seq, r.OccurredAt, r.ActorID, r.Action, r.SubjectRef, detail, prev)
}
