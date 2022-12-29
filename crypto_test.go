package cryptem_test

import (
	"crypto/sha256"
	"os"
	"testing"

	"github.com/ejfhp/cryptem"
)

var password []byte = []byte("le sedicilettere")

func TestCrypt_EncodeAndDecode(t *testing.T) {
	sample := `Nel mezzo del cammin di nostra vita
	mi ritrovai per una selva oscura,
	ché la diritta via era smarrita.`
	encoded, err := cryptem.Encrypt([]byte(password), []byte(sample))
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	decoded, err := cryptem.Decrypt([]byte(password), encoded)
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	if string(decoded) != sample {
		t.Fatalf("encrypt and decrypt has failed: %s != %s", string(decoded), sample)

	}
}

func TestCrypt_EncodeAndDecodeFile(t *testing.T) {
	clear := "testdata/img.png"
	encrypted := "testdata/img.png" + cryptem.EncryptedExtension
	decrypted := "testdata/img.png.dec"
	os.Remove(encrypted)
	os.Remove(decrypted)
	err := cryptem.EncryptFile([]byte(password), clear, clear+cryptem.EncryptedExtension)
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}

	err = cryptem.DecryptFile([]byte(password), clear+cryptem.EncryptedExtension, clear+".dec")
	if err != nil {
		t.Fatalf("cannot decrypt: %v", err)
	}

	clearData, err := os.ReadFile(clear)
	if err != nil {
		t.Fatalf("cannot read clear file: %v", err)
	}
	decodedData, err := os.ReadFile(clear + ".dec")
	if err != nil {
		t.Fatalf("cannot read clear file: %v", err)
	}

	for i, b := range sha256.Sum256(clearData) {
		if b != sha256.Sum256(decodedData)[i] {
			t.Fatalf("encrypt and decrypt of file has failed")
		}
	}
	os.Remove(encrypted)
	os.Remove(decrypted)
}
