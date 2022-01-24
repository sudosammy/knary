package cmd

import (
	"log"
	"os"
	"path/filepath"
)

func CreateFolderStructure() {
	folder := filepath.Join(GetCertPath(), "archives")
	err := os.MkdirAll(folder, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
}
