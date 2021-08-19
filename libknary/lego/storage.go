package cmd

import (
	"log"
	"os"
	"path/filepath"
)

func CreateFolderStructure() {
	folder := filepath.Join(baseArchivesFolderName)
	err := os.MkdirAll(folder, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
}
