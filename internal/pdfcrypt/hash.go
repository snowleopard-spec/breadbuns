// Package pdfcrypt implements the PDF 2.0 (ISO 32000-2) "Standard Security
// Handler" revision 6, i.e. AES-256 password encryption as used by modern
// Adobe Acrobat: the scheme behind the native "this document is protected"
// password prompt.
package pdfcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
)

// hash2B implements the "hardened" hash algorithm from ISO 32000-2
// 7.6.4.3.4 ("Algorithm 2.B"), used to derive both validation hashes and
// key-derivation hashes for revision 6.
func hash2B(password, salt, extra []byte) []byte {
	input := append(append(append([]byte{}, password...), salt...), extra...)
	k := sha256sum(input)

	round := 0
	for {
		k1 := bytes.Repeat(append(append(append([]byte{}, password...), k...), extra...), 64)
		e := aesCBCNoPadEncrypt(k[0:16], k[16:32], k1)

		sum := 0
		for _, b := range e[0:16] {
			sum += int(b)
		}
		switch sum % 3 {
		case 0:
			k = sha256sum(e)
		case 1:
			s := sha512.Sum384(e)
			k = s[:]
		case 2:
			s := sha512.Sum512(e)
			k = s[:]
		}

		round++
		if round >= 64 && int(e[len(e)-1]) <= round-32 {
			break
		}
	}
	return k[0:32]
}

func sha256sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// aesCBCNoPadEncrypt encrypts data (must be a multiple of the AES block
// size) with AES-CBC and no padding, using the given key/iv.
func aesCBCNoPadEncrypt(key, iv, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // key length is always valid here (16 or 32 bytes)
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return out
}

func aesCBCNoPadDecrypt(key, iv, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out
}
