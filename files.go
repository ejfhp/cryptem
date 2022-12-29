package cryptem

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	EncryptedExtension = ".cryptem"
	Unset              = iota
	ModeEncrypt
	ModeDecrypt
	ScanRecursive
	ScanLocal
	ForceNothing
	ForceDelete
	ForceOverwrite
	ForceDeleteAndOverwrite
)

func ProcessFile(key []byte, filePath string, force int) (string, error) {
	fileExt := filepath.Ext(filePath)
	var procFilePath string
	if fileExt == EncryptedExtension {
		procFilePath = strings.TrimSuffix(filePath, fileExt)
	} else {
		procFilePath = filePath + EncryptedExtension

	}
	exist, err := IsExisting(procFilePath)
	if err != nil {
		return "", err
	}
	if exist && force != ForceOverwrite && force != ForceDeleteAndOverwrite {
		return "", ErrFileExist
	}

	if filepath.Ext(procFilePath) == EncryptedExtension {
		err = EncryptFile(key, filePath, procFilePath)
		if err != nil {
			return "", err
		}
	} else {
		err = DecryptFile(key, filePath, procFilePath)
		if err != nil {
			return "", err
		}

	}
	if force == ForceDelete || force == ForceDeleteAndOverwrite {
		os.Remove(filePath)
	}
	return procFilePath, nil

}

func Scan(key []byte, folder string, scanmode int, mode int, force int) error {
	fmt.Printf("Scanning %s\n", folder)
	entries, err := os.ReadDir(folder)
	if err != nil {
		return err
	}
	currentFilePath := ""
	processedFilePath := ""
	for _, ent := range entries {
		if strings.HasPrefix(ent.Name(), ".") {
			// fmt.Printf("ignoring : %s\n", ent.Name())
			continue
		}
		currentFilePath = filepath.Join(folder, ent.Name())
		if ent.IsDir() && scanmode == ScanRecursive {
			err = Scan(key, currentFilePath, scanmode, mode, force)
			if err != nil {
				return fmt.Errorf("error while scanning '%s': %w", currentFilePath, err)
			}
		} else {
			if strings.HasSuffix(ent.Name(), EncryptedExtension) && mode == ModeEncrypt {
				// fmt.Printf("ignoring encrypted with mode encrypt: %s\n", ent.Name())
				continue
			}
			if !strings.HasSuffix(ent.Name(), EncryptedExtension) && mode == ModeDecrypt {
				// fmt.Printf("ignoring decrypted with mode decrypt: %s\n", ent.Name())
				continue
			}
			fmt.Printf("Processing %s to ", currentFilePath)
			processedFilePath, err = ProcessFile(key, currentFilePath, force)
			if err != nil {
				if err == ErrFileExist {
					fmt.Printf("File %s exists, ignored.", currentFilePath)
				} else {
					return fmt.Errorf("error while processing '%s': %w", currentFilePath, err)
				}
				continue
			}
			fmt.Printf("%s.\n", processedFilePath)
		}
	}
	return nil
}

func IsExisting(filePath string) (bool, error) {
	_, err := os.Stat(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("unable to check if file exixs: %w", err)
	}
	return true, nil
}

func HashOfFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error while reading file '%s': %w", filePath, err)
	}
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}
