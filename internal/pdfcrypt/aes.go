package pdfcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// EncryptData encrypts plaintext for storage in a string or stream: a
// random 16-byte IV followed by AES-256-CBC/PKCS7 ciphertext, using the
// 32-byte file encryption key directly (as specified for crypt filter
// AESV3 / V5).
func EncryptData(fileKey, plaintext []byte) ([]byte, error) {
	if len(fileKey) != 32 {
		return nil, errors.New("pdfcrypt: file key must be 32 bytes")
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, 16)
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append(iv, ct...), nil
}

// DecryptData reverses EncryptData.
func DecryptData(fileKey, data []byte) ([]byte, error) {
	if len(fileKey) != 32 {
		return nil, errors.New("pdfcrypt: file key must be 32 bytes")
	}
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < 16 || (len(data)-16)%16 != 0 {
		return nil, errors.New("pdfcrypt: malformed encrypted data")
	}
	iv, ct := data[:16], data[16:]
	if len(ct) == 0 {
		return nil, nil
	}
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	return pkcs7Unpad(pt)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	padLen := int(data[len(data)-1])
	if padLen <= 0 || padLen > 16 || padLen > len(data) {
		return nil, errors.New("pdfcrypt: invalid PKCS7 padding")
	}
	return data[:len(data)-padLen], nil
}

// aesECBNoPadBlocks encrypts/decrypts data (a multiple of 16 bytes) in AES
// ECB mode with no padding, used only for the 16-byte /Perms entry.
func aesECBEncrypt(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	for i := 0; i+16 <= len(data); i += 16 {
		block.Encrypt(out[i:i+16], data[i:i+16])
	}
	return out
}

func aesECBDecrypt(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	for i := 0; i+16 <= len(data); i += 16 {
		block.Decrypt(out[i:i+16], data[i:i+16])
	}
	return out
}
