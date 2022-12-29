package cryptem_test

import (
	"os"
	"testing"

	"github.com/ejfhp/cryptem"
)

func TestFiles_ProcessNotExisting(t *testing.T) {
	fileStart := "testdata/clear1.txt"
	fileExpected := "testdata/clear1.txt" + cryptem.EncryptedExtension
	os.Remove(fileStart)
	os.Remove(fileExpected)
	os.WriteFile(fileStart, []byte("test data"), 0666)

	res, err := cryptem.ProcessFile(password, fileStart, cryptem.Unset)
	if err != nil {
		t.Fatalf("error processing file: %v", err)
	}
	exist, err := cryptem.IsExisting(fileExpected)
	if err != nil {
		t.Fatalf("error checking if file exist: %v", err)
	}
	if !exist {
		t.Fatalf("file has not been created: %v", err)
	}
	if res != fileExpected {
		t.Fatalf("unexpected file name: %s", res)
	}
	err = os.Remove(fileStart)
	if err != nil {
		t.Fatalf("error deleting test file: %v", err)
	}
	err = os.Remove(fileExpected)
	if err != nil {
		t.Fatalf("error deleting test file: %v", err)
	}
}

func TestFiles_ProcessExistingNoForce(t *testing.T) {
	fileStart := "testdata/clear1.txt"
	fileExpected := "testdata/clear1.txt" + cryptem.EncryptedExtension
	os.Remove(fileStart)
	os.Remove(fileExpected)
	os.WriteFile(fileStart, []byte("test data"), 0666)
	os.WriteFile(fileExpected, []byte("test data crypted"), 0666)

	hashBefore, err := cryptem.HashOfFile(fileExpected)
	if err != nil {
		t.Fatalf("error getting hash of file: %v", err)
	}
	res, err := cryptem.ProcessFile(password, fileStart, cryptem.Unset)
	if err != nil && err != cryptem.ErrFileExist {
		t.Fatalf("error processing file: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("file name is not empty: '%s'", res)
	}
	hashAfter, err := cryptem.HashOfFile(fileExpected)
	if hashBefore != hashAfter {
		t.Fatalf("file has been modified: %v", err)
	}
	err = os.Remove(fileStart)
	if err != nil {
		t.Fatalf("error deleting test file: %v", err)
	}
	err = os.Remove(fileExpected)
	if err != nil {
		t.Fatalf("error deleting test file: %v", err)
	}
}

func TestFiles_ProcessExistingForceOverwrite(t *testing.T) {
	fileStart := "testdata/clear1.txt"
	fileExpected := "testdata/clear1.txt" + cryptem.EncryptedExtension
	os.Remove(fileStart)
	os.Remove(fileExpected)
	os.WriteFile(fileStart, []byte("test data"), 0666)
	os.WriteFile(fileExpected, []byte("test data crypted"), 0666)

	hashBefore, err := cryptem.HashOfFile(fileExpected)
	if err != nil {
		t.Fatalf("error getting hash of file: %v", err)
	}
	res, err := cryptem.ProcessFile(password, fileStart, cryptem.ForceOverwrite)
	if err != nil {
		t.Fatalf("error processing file: %v", err)
	}
	if res != fileExpected {
		t.Fatalf("file name is unexpected: '%s'", res)
	}
	hashAfter, err := cryptem.HashOfFile(fileExpected)
	if hashBefore == hashAfter {
		t.Fatalf("file has not been modified: %v", err)
	}
	err = os.Remove(fileStart)
	if err != nil {
		t.Fatalf("error deleting test file: %v", err)
	}
	err = os.Remove(fileExpected)
	if err != nil {
		t.Fatalf("error deleting test file: %v", err)
	}
}

func TestFiles_ProcessAndDelete(t *testing.T) {
	fileStart := "testdata/clear1.txt"
	fileExpected := "testdata/clear1.txt" + cryptem.EncryptedExtension
	os.Remove(fileStart)
	os.Remove(fileExpected)
	os.WriteFile(fileStart, []byte("test data"), 0666)

	res, err := cryptem.ProcessFile(password, fileStart, cryptem.ForceDeleteAndOverwrite)
	if err != nil {
		t.Fatalf("error processing file: %v", err)
	}
	if res != fileExpected {
		t.Fatalf("file name is unexpected: '%s'", res)
	}
	exist, err := cryptem.IsExisting(fileStart)
	if err != nil {
		t.Fatalf("error checking if file exist: %v", err)
	}
	if exist {
		t.Fatalf("start file should not exist: '%s'", fileStart)

	}
	err = os.Remove(fileExpected)
	if err != nil {
		t.Fatalf("error deleting test file: %v", err)
	}

}

func TestFiles_Scan(t *testing.T) {
	t.SkipNow()
	err := cryptem.Scan(password, "/fakefolder/fakefolder", cryptem.ScanLocal, cryptem.ModeDecrypt, cryptem.ForceDelete)
	if err != nil {
		t.Fatalf("error scannning test folder: %v", err)
	}
}

func TestFiles_HashOfFile(t *testing.T) {
	fileStart := "testdata/hash.txt"
	os.WriteFile(fileStart, []byte("test data"), 0666)
	hash, err := cryptem.HashOfFile(fileStart)
	if err != nil {
		t.Fatalf("error calculating hash of file: %v", err)
	}
	if len(hash) < 30 {
		t.Fatalf("hash too short: %s", hash)

	}
	os.Remove(fileStart)

}
