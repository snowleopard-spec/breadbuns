package pdfcrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"breadbuns/internal/pdf"
)

// ErrIncorrectPassword is returned by Authenticate when the supplied
// password matches neither the user nor owner password.
var ErrIncorrectPassword = errors.New("incorrect password")

// preparePassword converts a password to the byte form used by the
// algorithm: UTF-8 bytes, truncated to 127 bytes per spec.
func preparePassword(pw string) []byte {
	b := []byte(pw)
	if len(b) > 127 {
		b = b[:127]
	}
	return b
}

// GenerateFileKey returns a fresh random 32-byte AES-256 file encryption key.
func GenerateFileKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// BuildEncryptDict builds a PDF 2.0 /Encrypt dictionary (Standard security
// handler, V5/R6, AES-256) that protects fileKey with password, used as
// both the user and owner password (this tool has no separate "owner"
// concept: one password both opens and fully controls the file).
func BuildEncryptDict(password string, fileKey []byte) pdf.Dict {
	pw := preparePassword(password)

	valSaltU := randBytes(8)
	keySaltU := randBytes(8)
	hashU := hash2B(pw, valSaltU, nil)
	U := concat(hashU, valSaltU, keySaltU)
	interKeyU := hash2B(pw, keySaltU, nil)
	UE := aesCBCNoPadEncrypt(interKeyU, zeroIV(), fileKey)

	valSaltO := randBytes(8)
	keySaltO := randBytes(8)
	hashO := hash2B(pw, valSaltO, U)
	O := concat(hashO, valSaltO, keySaltO)
	interKeyO := hash2B(pw, keySaltO, U)
	OE := aesCBCNoPadEncrypt(interKeyO, zeroIV(), fileKey)

	const p = int32(-4) // all permission bits granted
	perms := buildPerms(fileKey, p, true)

	return pdf.Dict{
		"Filter":          pdf.Name("Standard"),
		"V":               int64(5),
		"R":               int64(6),
		"Length":          int64(256),
		"P":               int64(p),
		"O":               pdf.String{Bytes: O},
		"U":               pdf.String{Bytes: U},
		"OE":              pdf.String{Bytes: OE},
		"UE":              pdf.String{Bytes: UE},
		"Perms":           pdf.String{Bytes: perms},
		"EncryptMetadata": true,
		"CF": pdf.Dict{
			"StdCF": pdf.Dict{
				"CFM":       pdf.Name("AESV3"),
				"AuthEvent": pdf.Name("DocOpen"),
				"Length":    int64(32),
			},
		},
		"StmF": pdf.Name("StdCF"),
		"StrF": pdf.Name("StdCF"),
	}
}

func buildPerms(fileKey []byte, p int32, encryptMetadata bool) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], uint32(p))
	b[4], b[5], b[6], b[7] = 0xFF, 0xFF, 0xFF, 0xFF
	if encryptMetadata {
		b[8] = 'T'
	} else {
		b[8] = 'F'
	}
	b[9], b[10], b[11] = 'a', 'd', 'b'
	copy(b[12:16], randBytes(4))
	return aesECBEncrypt(fileKey, b)
}

// Authenticate checks password against an /Encrypt dictionary produced by
// BuildEncryptDict (V5, R5 or R6) and, if it matches, returns the recovered
// 32-byte file encryption key.
func Authenticate(encDict pdf.Dict, password string) ([]byte, error) {
	v, _ := asInt(encDict["V"])
	r, _ := asInt(encDict["R"])
	if v != 5 || (r != 5 && r != 6) {
		return nil, fmt.Errorf("unsupported encryption (V=%d R=%d): breadbuns can only decrypt AES-256 (V5/R6) files", v, r)
	}
	// Acrobat (and some other writers) emit /U and /O as 127-byte strings:
	// the 48 significant bytes followed by zero padding. The spec only
	// defines the first 48 bytes, so accept anything at least that long and
	// use just the significant prefix.
	U := first48(asBytes(encDict["U"]))
	UE := asBytes(encDict["UE"])
	O := first48(asBytes(encDict["O"]))
	OE := asBytes(encDict["OE"])
	if len(U) != 48 || len(UE) != 32 {
		return nil, errors.New("malformed /U or /UE in encryption dictionary")
	}
	pw := preparePassword(password)

	hash := hash2B(pw, U[32:40], nil)
	if subtle.ConstantTimeCompare(hash, U[0:32]) == 1 {
		interKey := hash2B(pw, U[40:48], nil)
		return aesCBCNoPadDecrypt(interKey, zeroIV(), UE), nil
	}

	if len(O) == 48 && len(OE) == 32 {
		hashO := hash2B(pw, O[32:40], U)
		if subtle.ConstantTimeCompare(hashO, O[0:32]) == 1 {
			interKeyO := hash2B(pw, O[40:48], U)
			return aesCBCNoPadDecrypt(interKeyO, zeroIV(), OE), nil
		}
	}

	return nil, ErrIncorrectPassword
}

func zeroIV() []byte { return make([]byte, 16) }

// first48 returns the first 48 bytes of b (the spec-defined portion of a
// V5 /U or /O string), or b unchanged if it is shorter.
func first48(b []byte) []byte {
	if len(b) > 48 {
		return b[:48]
	}
	return b
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func asInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

func asBytes(v interface{}) []byte {
	if s, ok := v.(pdf.String); ok {
		return s.Bytes
	}
	return nil
}
