package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"breadbuns/internal/pdf"
)

// testdata/acrobat_aes256.pdf was encrypted by Adobe Acrobat (AES-256,
// V5/R6, linearized, objects stored in object streams, /U and /O padded to
// 127 bytes) with the password "claude". It exercises the parts of the
// decrypt path that breadbuns' own output never does.
func TestDecryptAcrobatFile(t *testing.T) {
	original, err := os.ReadFile(filepath.Join("testdata", "acrobat_aes256.pdf"))
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "acrobat.pdf")
	if err := os.WriteFile(src, original, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := decryptFile(src, "wrong"); err == nil {
		t.Fatalf("expected wrong password to be rejected")
	}
	if warn, err := decryptFile(src, "claude"); err != nil {
		t.Fatalf("decryptFile: %v", err)
	} else if warn != "" {
		t.Fatalf("unexpected /Perms warning on a well-formed file: %s", warn)
	}

	doc, err := pdf.Load(src)
	if err != nil {
		t.Fatalf("loading decrypted file: %v", err)
	}
	if doc.IsEncrypted() {
		t.Fatalf("still encrypted after decrypt")
	}
	// The page tree (which lived in an object stream) must be reachable
	// and intact: /Root -> /Pages -> /Count 3.
	root, _ := doc.Resolve(doc.Trailer()["Root"]).(pdf.Dict)
	if root == nil {
		t.Fatalf("/Root not resolvable")
	}
	pages, _ := doc.Resolve(root["Pages"]).(pdf.Dict)
	if pages == nil {
		t.Fatalf("/Pages not resolvable (object-stream members lost?)")
	}
	if n, _ := pages["Count"].(int64); n != 3 {
		t.Fatalf("expected /Count 3, got %v", pages["Count"])
	}

	// Re-lock with breadbuns and unlock again: a full round trip on a file
	// that did not originate from breadbuns.
	if err := encryptFile(src, "again"); err != nil {
		t.Fatalf("encryptFile: %v", err)
	}
	locked := filepath.Join(dir, "acrobat_locked.pdf")
	if _, err := decryptFile(locked, "again"); err != nil {
		t.Fatalf("decryptFile (round trip): %v", err)
	}

	qpdfPath, err := exec.LookPath("qpdf")
	if err != nil {
		t.Skip("qpdf not installed; skipping independent validation")
	}
	for _, f := range []string{src, locked} {
		out, err := exec.Command(qpdfPath, "--check", f).CombinedOutput()
		if err != nil {
			t.Errorf("qpdf --check %s failed: %v\n%s", filepath.Base(f), err, out)
		}
		np, _ := exec.Command(qpdfPath, "--show-npages", f).Output()
		if strings.TrimSpace(string(np)) != "3" {
			t.Errorf("qpdf reports %q pages for %s, want 3", strings.TrimSpace(string(np)), filepath.Base(f))
		}
	}
}

// testdata/cleartext_metadata.pdf is the same document re-encrypted by
// qpdf (AES-256 R6, password "claude") with /EncryptMetadata false, so
// its XMP metadata stream is stored in the clear and must survive
// decryption untouched rather than being "decrypted" into garbage.
func TestDecryptCleartextMetadata(t *testing.T) {
	original, err := os.ReadFile(filepath.Join("testdata", "cleartext_metadata.pdf"))
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "clearmeta.pdf")
	if err := os.WriteFile(src, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if warn, err := decryptFile(src, "claude"); err != nil {
		t.Fatalf("decryptFile: %v", err)
	} else if warn != "" {
		t.Fatalf("unexpected /Perms warning on a well-formed file: %s", warn)
	}

	doc, err := pdf.Load(src)
	if err != nil {
		t.Fatalf("loading decrypted file: %v", err)
	}
	root, _ := doc.Resolve(doc.Trailer()["Root"]).(pdf.Dict)
	meta, _ := doc.Resolve(root["Metadata"]).(*pdf.Stream)
	if meta == nil {
		t.Fatalf("/Root /Metadata stream missing after decrypt")
	}
	if !strings.Contains(string(meta.Data), "<?xpacket begin") {
		t.Fatalf("metadata stream corrupted: %.60q", meta.Data)
	}

	// And a breadbuns re-lock (which encrypts metadata) must round-trip.
	if err := encryptFile(src, "again"); err != nil {
		t.Fatalf("encryptFile: %v", err)
	}
	locked := filepath.Join(dir, "clearmeta_locked.pdf")
	if _, err := decryptFile(locked, "again"); err != nil {
		t.Fatalf("decryptFile (round trip): %v", err)
	}
	if qpdfPath, err := exec.LookPath("qpdf"); err == nil {
		for _, f := range []string{src, locked} {
			if out, err := exec.Command(qpdfPath, "--check", f).CombinedOutput(); err != nil {
				t.Errorf("qpdf --check %s failed: %v\n%s", filepath.Base(f), err, out)
			}
		}
	}
}
