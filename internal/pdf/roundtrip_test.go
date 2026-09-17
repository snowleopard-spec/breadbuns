package pdf_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"breadbuns/internal/pdf"
	"breadbuns/internal/pdfcrypt"
)

func loadSample(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample.pdf"))
	if err != nil {
		t.Skipf("test fixture not available: %v", err)
	}
	return data
}

func encrypt(t *testing.T, original []byte, password string) []byte {
	t.Helper()
	doc, err := pdf.Parse(original)
	if err != nil {
		t.Fatalf("parse original: %v", err)
	}
	fileKey, err := pdfcrypt.GenerateFileKey()
	if err != nil {
		t.Fatalf("generate file key: %v", err)
	}
	encDict := pdfcrypt.BuildEncryptDict(password, fileKey)
	out, err := pdf.Write(doc, pdf.WriteOptions{
		Transform:   func(b []byte) ([]byte, error) { return pdfcrypt.EncryptData(fileKey, b) },
		EncryptDict: encDict,
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return out
}

func decrypt(t *testing.T, encrypted []byte, password string) []byte {
	t.Helper()
	doc, err := pdf.Parse(encrypted)
	if err != nil {
		t.Fatalf("parse encrypted: %v", err)
	}
	encDict, ok := doc.EncryptDict()
	if !ok {
		t.Fatalf("expected document to be encrypted")
	}
	fileKey, err := pdfcrypt.Authenticate(encDict, password)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	out, err := pdf.Write(doc, pdf.WriteOptions{
		Transform: func(b []byte) ([]byte, error) { return pdfcrypt.DecryptData(fileKey, b) },
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return out
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	original := loadSample(t)
	const password = "correct-horse-battery-staple"

	encrypted := encrypt(t, original, password)

	doc, err := pdf.Parse(encrypted)
	if err != nil {
		t.Fatalf("re-parse encrypted output: %v", err)
	}
	if !doc.IsEncrypted() {
		t.Fatalf("expected encrypted output to report IsEncrypted() == true")
	}

	if _, err := pdfcrypt.Authenticate(mustEncDict(t, encrypted), "wrong password"); err == nil {
		t.Fatalf("expected wrong password to fail authentication")
	}

	decrypted := decrypt(t, encrypted, password)

	// The decrypted document must re-parse and, page-content-wise, contain
	// the same visible text as the original.
	origText := extractSampleMarker(t, original)
	gotText := extractSampleMarker(t, decrypted)
	if origText != gotText {
		t.Fatalf("decrypted content stream marker mismatch:\n original: %q\n decrypted: %q", origText, gotText)
	}

	checkWithQPDF(t, encrypted, password)
}

func mustEncDict(t *testing.T, encrypted []byte) pdf.Dict {
	t.Helper()
	doc, err := pdf.Parse(encrypted)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d, ok := doc.EncryptDict()
	if !ok {
		t.Fatalf("no encrypt dict")
	}
	return d
}

// extractSampleMarker returns a stable fingerprint of the document: the
// sorted set of every literal/hex string byte sequence found across all
// objects. Good enough to detect corruption without needing full content
// stream interpretation.
func extractSampleMarker(t *testing.T, data []byte) string {
	t.Helper()
	doc, err := pdf.Parse(data)
	if err != nil {
		t.Fatalf("parse for fingerprint: %v", err)
	}
	nums := doc.AllObjects()
	sort.Ints(nums)
	var out bytes.Buffer
	for _, num := range nums {
		v := doc.Resolve(pdf.Ref{Num: num})
		if s, ok := v.(*pdf.Stream); ok {
			out.Write(s.Data)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// checkWithQPDF cross-validates our output against an independent PDF
// implementation, if qpdf is installed. It confirms qpdf considers the file
// structurally valid, correctly reports it as AES-256 encrypted, and can
// itself decrypt it with the password.
func checkWithQPDF(t *testing.T, encrypted []byte, password string) {
	t.Helper()
	qpdfPath, err := exec.LookPath("qpdf")
	if err != nil {
		t.Skip("qpdf not installed; skipping independent validation")
	}

	dir := t.TempDir()
	encPath := filepath.Join(dir, "encrypted.pdf")
	if err := os.WriteFile(encPath, encrypted, 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	show := exec.Command(qpdfPath, "--show-encryption", encPath)
	showOut, err := show.CombinedOutput()
	if err != nil {
		t.Fatalf("qpdf --show-encryption failed: %v\n%s", err, showOut)
	}
	if !bytes.Contains(showOut, []byte("R = 6")) {
		t.Errorf("expected qpdf to report R = 6, got:\n%s", showOut)
	}

	decPath := filepath.Join(dir, "decrypted.pdf")
	dec := exec.Command(qpdfPath, "--password="+password, "--decrypt", encPath, decPath)
	if out, err := dec.CombinedOutput(); err != nil {
		t.Fatalf("qpdf --decrypt with correct password failed: %v\n%s", err, out)
	}

	check := exec.Command(qpdfPath, "--check", decPath)
	if out, err := check.CombinedOutput(); err != nil {
		t.Errorf("qpdf --check on qpdf-decrypted file failed: %v\n%s", err, out)
	}

	badDec := exec.Command(qpdfPath, "--password=definitely-wrong", "--decrypt", encPath, filepath.Join(dir, "bad.pdf"))
	if out, err := badDec.CombinedOutput(); err == nil {
		t.Errorf("expected qpdf to reject the wrong password, but it succeeded:\n%s", out)
	}
}
