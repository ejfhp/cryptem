package cryptem_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/ejfhp/cryptem"
)

var password []byte = []byte("12345678901234567890123456789012")

func TestCrypto_EncodeAndDecode(t *testing.T) {
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

//TODO Encoding has to be repeatable, same file encoded two times must be exactly the same
func TestCrypto_VerifyEncoding(t *testing.T) {
	sample := `Nel mezzo del cammin di nostra vita
	mi ritrovai per una selva oscura,
	ché la diritta via era smarrita.`
	encoded1, err := cryptem.Encrypt([]byte(password), []byte(sample))
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}
	encoded2, err := cryptem.Encrypt([]byte(password), []byte(sample))
	if err != nil {
		t.Fatalf("cannot encrypt: %v", err)
	}
	sum1 := sha256.Sum256(encoded1)
	sum2 := sha256.Sum256(encoded2)
	for i, b := range sum1 {
		if b != sum2[i] {
			t.Fatalf("not same sum")
		}
	}
}

func TestCrypto_EncodeAndDecodeFile(t *testing.T) {
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

func TestCrypto_EncodeDecodeName(t *testing.T) {
	name := "folder_name"
	encoded, err := cryptem.CryptEncodeName(password, name)
	if err != nil {
		t.Fatalf("error encoding name: %v", err)
	}
	fmt.Printf("%s encoded to %s \n", name, encoded)
	decoded, err := cryptem.CryptDecodeName(password, encoded)
	if err != nil {
		t.Fatalf("error decoding name: %v", err)
	}
	if name != decoded {
		t.Fatalf("source '%s' and decoded '%s' don't match", name, decoded)

	}
}
