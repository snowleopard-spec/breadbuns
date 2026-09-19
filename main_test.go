package main

import (
	"os"
	"path/filepath"
	"testing"

	"breadbuns/internal/pdf"
)

func TestEncryptFileThenDecryptFile(t *testing.T) {
	original, err := os.ReadFile(filepath.Join("testdata", "sample.pdf"))
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "sample.pdf")
	if err := os.WriteFile(src, original, 0o644); err != nil {
		t.Fatal(err)
	}

	const password = "hunter2-hunter2"
	if err := encryptFile(src, password); err != nil {
		t.Fatalf("encryptFile: %v", err)
	}

	// Original must be untouched.
	stillThere, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("original disappeared: %v", err)
	}
	if string(stillThere) != string(original) {
		t.Fatalf("original file was modified by encryptFile")
	}

	locked := filepath.Join(dir, "sample_locked.pdf")
	if _, err := os.Stat(locked); err != nil {
		t.Fatalf("expected locked copy at %s: %v", locked, err)
	}
	lockedDoc, err := pdf.Load(locked)
	if err != nil {
		t.Fatalf("loading locked copy: %v", err)
	}
	if !lockedDoc.IsEncrypted() {
		t.Fatalf("locked copy is not reported as encrypted")
	}

	if _, err := decryptFile(locked, "wrong password"); err == nil {
		t.Fatalf("expected decryptFile to fail with wrong password")
	}
	// File must be untouched after a failed decrypt attempt.
	afterFail, err := pdf.Load(locked)
	if err != nil {
		t.Fatalf("locked copy unreadable after failed decrypt: %v", err)
	}
	if !afterFail.IsEncrypted() {
		t.Fatalf("locked copy lost its encryption after a failed decrypt attempt")
	}

	if _, err := decryptFile(locked, password); err != nil {
		t.Fatalf("decryptFile: %v", err)
	}
	finalDoc, err := pdf.Load(locked)
	if err != nil {
		t.Fatalf("loading decrypted file: %v", err)
	}
	if finalDoc.IsEncrypted() {
		t.Fatalf("file is still reported as encrypted after decryptFile")
	}
}
