package main

import "flag"

const (
	flagPassword = "password"
	flagDelete   = "delete"
	flagScan     = "scan"
	flagDecrypt  = "decrypt"
	flagSingle   = "single"
	taskEncrypt  = iota
	taskDecrypt
)

var (
	parPassword string
	parDelete   bool   //clear files when encrypting, encrypted files when decrypting
	parScan     bool   //scan subfolders
	parDecrypt  bool   //decrypt
	parSingle   string //encrypt/decrypt a single file
)

func main() {
	flag.StringVar(&parPassword, flagPassword, "", "password to encrypt/decrypt files")
	flag.BoolVar(&parDelete, flagDelete, "", "clear files when encrypting, encrypted files when decrypting")
	flag.BoolVar(&parScan, flagScan, "", "scan subfolder")
	flag.BoolVar(&parDecrypt, flagDecrypt, "", "decrypt instead of encrypt")
	flag.StringVar(&parSingle, flagPassword, "", "encrypt/decrypt a single file")
	flag.Parse()

	action := taskEncrypt
	if isSet(flagDecrypt) {
		action = taskDecrypt
	}

}

func isSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
