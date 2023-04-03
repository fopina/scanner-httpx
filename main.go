package main

import (
	"io"
	"log"
	"os"
	"path"

	"github.com/surface-security/scanner-go-entrypoint/scanner"
)

func main() {
	s := scanner.Scanner{Name: "httpx"}
	options := s.BuildOptions()
	scanner.ParseOptions(options)

	err := os.MkdirAll(options.Output, 0755)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// pass temporary file to binary instead of final path, as only finished files should be placed there
	file, err := os.CreateTemp("", s.Name)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer os.Remove(file.Name())

	err = s.Exec(
		"-silent", "-no-fallback", "-pipeline", "-tech-detect",
		"-json", "-o", file.Name(),
		"-l", options.Input,
	)
	if err != nil {
		log.Fatalf("Failed to run scanner: %v", err)
	}

	realOutputFile := path.Join(options.Output, "output.txt")
	outputFile, err := os.Create(realOutputFile)
	if err != nil {
		log.Fatalf("Couldn't open dest file: %v", err)
	}
	defer outputFile.Close()
	_, err = io.Copy(outputFile, file)
	if err != nil {
		log.Fatalf("Writing to output file failed: %v", err)
	}
}
