package main

import (
	"flag"
	"fmt"

	"github.com/ejfhp/cryptem"
)

const (
	flagPassword  = "password"
	flagFolder    = "folder"
	flagDelete    = "delete"
	flagOverwrite = "overwrite"
	flagRecursive = "recursive"
	flagDecrypt   = "decrypt"
	taskEncrypt   = iota
	taskDecrypt
)

var (
	parPassword  string
	parFolder    string
	parDelete    bool //clear files when encrypting, encrypted files when decrypting
	parRecursive bool //scan subfolders
	parOverwrite bool
	parDecrypt   bool //decrypt
)

func printHelp() {
	flag.PrintDefaults()
}

func main() {
	flag.StringVar(&parPassword, flagPassword, "", "password to encrypt/decrypt files")
	flag.StringVar(&parFolder, flagFolder, "", "folder to scan to encrypt/decrypt files")
	flag.BoolVar(&parDelete, flagDelete, false, "delete clear files when encrypting, encrypted files when decrypting")
	flag.BoolVar(&parOverwrite, flagOverwrite, false, "overwrite target file if exists")
	flag.BoolVar(&parRecursive, flagRecursive, false, "recursive scan")
	flag.BoolVar(&parDecrypt, flagDecrypt, false, "decrypt instead of encrypt")

	flag.Parse()
	if flag.NFlag() < 2 {
		printHelp()
		return
	}
	if len(parPassword) == 0 || len(parFolder) == 0 {
		printHelp()
		return
	}
	password := []byte(parPassword)
	if len(password) != 16 {
		fmt.Printf("AES password must be 16 chars long\n")
		return
	}
	folder := parFolder

	mode := cryptem.ModeEncrypt
	if parDecrypt {
		mode = cryptem.ModeDecrypt
	}

	fmt.Printf("Delete: %t\n", parDelete)

	force := cryptem.ForceNothing
	if parDelete && parOverwrite {
		force = cryptem.ForceDeleteAndOverwrite
	} else if parDelete {
		force = cryptem.ForceDelete
	} else if parOverwrite {
		force = cryptem.ForceOverwrite
	}

	scan := cryptem.ScanLocal
	if parRecursive {
		scan = cryptem.ScanRecursive
	}

	err := cryptem.Scan(password, folder, scan, mode, force)
	if err != nil {
		fmt.Printf("cryptem failed: %v\n\n", err)
	}

}

// func isSet(name string) bool {
// 	set := false
// 	flag.Visit(func(f *flag.Flag) {
// 		if f.Name == name {
// 			set = true
// 		}
// 	})
// 	return set
// }
