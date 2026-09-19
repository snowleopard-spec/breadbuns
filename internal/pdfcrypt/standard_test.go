package pdfcrypt

import (
	"testing"

	"breadbuns/internal/pdf"
)

func TestVerifyPerms(t *testing.T) {
	key, err := GenerateFileKey()
	if err != nil {
		t.Fatal(err)
	}
	d := BuildEncryptDict("pw", key)
	got, err := Authenticate(d, "pw")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if err := VerifyPerms(d, got); err != nil {
		t.Fatalf("well-formed dict failed VerifyPerms: %v", err)
	}

	// Flip one ciphertext byte: the marker no longer decrypts.
	tampered := pdf.Clone(d).(pdf.Dict)
	perms := tampered["Perms"].(pdf.String)
	perms.Bytes[15] ^= 0x01
	tampered["Perms"] = perms
	if err := VerifyPerms(tampered, got); err == nil {
		t.Fatalf("tampered /Perms block passed")
	}

	// Alter /P without re-sealing the block: permissions disagree.
	altered := pdf.Clone(d).(pdf.Dict)
	altered["P"] = int64(-1)
	if err := VerifyPerms(altered, got); err == nil {
		t.Fatalf("altered /P passed")
	}

	// Alter /EncryptMetadata without re-sealing: flag disagrees.
	meta := pdf.Clone(d).(pdf.Dict)
	meta["EncryptMetadata"] = false
	if err := VerifyPerms(meta, got); err == nil {
		t.Fatalf("altered /EncryptMetadata passed")
	}

	// Missing block.
	missing := pdf.Clone(d).(pdf.Dict)
	delete(missing, "Perms")
	if err := VerifyPerms(missing, got); err == nil {
		t.Fatalf("missing /Perms passed")
	}
}
