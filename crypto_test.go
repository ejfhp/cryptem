package cryptem_test

import (
	"testing"

	"github.com/ejfhp/cryptem"
)

func TestCrypt_EncodeAndDecode(t *testing.T) {
	sample := `Nel mezzo del cammin di nostra vita
	mi ritrovai per una selva oscura,
	ché la diritta via era smarrita.`
	password := "le sedicilettere"
	encoded, err := cryptem.Encrypt([]byte(sample), []byte(password))
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	decoded, err := cryptem.Decrypt(encoded, []byte(password))
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if string(decoded) != sample {
		t.Fatalf("encrypt and decrypt has failed: %s != %s", string(decoded), sample)

	}
}
