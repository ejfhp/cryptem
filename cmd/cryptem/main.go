package main

import (
	"crypto/sha256"
	"flag"
	"fmt"

	"github.com/ejfhp/cryptem"
)

const (
	flagPassword   = "password"
	flagPassphrase = "passphrase"
	flagFolder     = "folder"
	flagDelete     = "delete"
	flagOverwrite  = "overwrite"
	flagRecursive  = "recursive"
	flagDecrypt    = "decrypt"
	taskEncrypt    = iota
	taskDecrypt
)

var (
	parPassword   string
	parPassphrase string
	parFolder     string
	parDelete     bool //clear files when encrypting, encrypted files when decrypting
	parRecursive  bool //scan subfolders
	parOverwrite  bool
	parDecrypt    bool //decrypt
)

func printHelp() {
	flag.PrintDefaults()
}

func main() {
	flag.StringVar(&parPassword, flagPassword, "", "password to encrypt/decrypt files - 16 chars")
	flag.StringVar(&parPassphrase, flagPassphrase, "", "passphrase to encrypt/decrypt files - hashed sha256")
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
	if (len(parPassword) == 0 && len(parPassphrase) == 0) || (len(parPassword) != 0 && len(parPassphrase) != 0) {
		fmt.Printf("Only one betweent %s and %s must be given\n", flagPassword, flagPassphrase)
		printHelp()
		return
	}
	if len(parFolder) == 0 {
		fmt.Printf("Folder unset\n")
		printHelp()
		return
	}
	var password []byte
	if len(parPassphrase) > 0 {
		password = make([]byte, 16)
		s := sha256.Sum256([]byte(parPassphrase))
		copy(password, s[:16])
	} else {
		password = []byte(parPassword)
	}
	if len(password) != 16 {
		fmt.Printf("AES password must be 16 chars long: %d\n", len(password))
		return

	}
	folder := parFolder

	mode := cryptem.ModeEncrypt
	if parDecrypt {
		mode = cryptem.ModeDecrypt
	}

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
	printConfig(folder, scan, mode, force)
	err := cryptem.Scan(password, folder, scan, mode, force)
	if err != nil {
		fmt.Printf("\nERROR - cryptem failed: %v\n\n", err)
	}

}

func printConfig(folder string, scanmode int, mode int, force int) {
	fmt.Printf("Folder: %s\n", folder)
	switch scanmode {
	case cryptem.ScanLocal:
		fmt.Printf("Scan: local\n")
	case cryptem.ScanRecursive:
		fmt.Printf("Scan: recursive\n")
	default:
		fmt.Printf("Scan: undefined\n")
	}
	switch mode {
	case cryptem.ModeDecrypt:
		fmt.Printf("Mode: decrypt\n")
	case cryptem.ModeEncrypt:
		fmt.Printf("Mode: encrypt\n")
	default:
		fmt.Printf("Mode: undefined\n")
	}
	switch force {
	case cryptem.ForceDelete:
		fmt.Printf("Force: delete\n")
	case cryptem.ForceOverwrite:
		fmt.Printf("Force: overwrite\n")
	case cryptem.ForceDeleteAndOverwrite:
		fmt.Printf("Force: delete and overwrite\n")
	default:
		fmt.Printf("Force: undefined\n")
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
