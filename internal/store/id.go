package store

import (
	"crypto/rand"
	"encoding/hex"
)

// NewID returns a row id of the form "<prefix>-<random hex>".
//
// Short and typeable on purpose: these ids are what an operator passes to
// citadel and what §14.5's attestation report quotes back ("grant g-4f21"). Eight
// hex characters is 4 billion values per prefix, which is far past collision
// risk at this scale while staying readable in a terminal.
func NewID(prefix string) string {

	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {

		panic("store: crypto/rand failed: " + err.Error())
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}
