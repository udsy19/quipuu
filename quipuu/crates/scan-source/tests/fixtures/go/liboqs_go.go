// Fixture: liboqs-go's own construction shape, transcribed from its
// examples/kem/kem.go and examples/sig/sig.go (v0.16.0) — a zero-value
// struct followed by a separate .Init(name, nil) call the extractor does
// not trace. Backlog #Y77.
package main

import (
	"log"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func kemExample() {
	kemName := "ML-KEM-512"
	client := oqs.KeyEncapsulation{}
	defer client.Clean()

	if err := client.Init(kemName, nil); err != nil {
		log.Fatal(err)
	}
}

func sigExample() {
	sigName := "ML-DSA-44"
	signer := oqs.Signature{}
	defer signer.Clean()

	if err := signer.Init(sigName, nil); err != nil {
		log.Fatal(err)
	}
}
