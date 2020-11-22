package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"hash"
	"io"
)

const KEY_SIZE = 32 // bytes; AES-256 and SHA-256
const SALT_SIZE = 10
const HASH_SIZE = 32

type EncryptStream struct {
	cipher.StreamWriter
	IV [aes.BlockSize]byte
}

type DecryptStream struct {
	cipher.StreamReader
}

func NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha256.New, key[:])
}

func SHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func SHA256WithNewSalt(data []byte) ([]byte, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	bytes := make([]byte, SALT_SIZE)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}

	return SHA256WithPredefinedSalt(data, bytes), nil
}

func SHA256WithPredefinedSalt(data []byte, salt []byte) []byte {
	nSalt := make([]byte, len(salt))
	copy(nSalt, salt)

	nSalt = append(nSalt, []byte("::")...)
	h := SHA256(append(nSalt, data...))
	saltedHash := append(nSalt, h...)

	return saltedHash
}

func SHA256File(r io.Reader) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func DeriveKeys(masterKey string) (cipherKey [KEY_SIZE]byte, macKey [KEY_SIZE]byte) {
	h := NewHMAC([]byte(masterKey))

	h.Write([]byte("encryption key"))
	copy(cipherKey[:], h.Sum(nil))

	h.Reset()
	h.Write([]byte("hmac key"))
	copy(macKey[:], h.Sum(nil))
	return
}

func ConstantTimeCompare(h1 []byte, h2 []byte) bool {
	if subtle.ConstantTimeCompare(h1, h2) == 1 {
		return true
	}
	return false
}

func NewEncryptStream(key [KEY_SIZE]byte, target io.Writer) (*EncryptStream, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	e := &EncryptStream{}

	// Randomly init IV
	_, err = rand.Read(e.IV[:])
	if err != nil {
		return nil, err
	}

	// Init stream
	e.S = cipher.NewOFB(block, e.IV[:])

	// Set target
	e.W = target

	return e, nil
}

func NewDecryptStream(key [KEY_SIZE]byte, iv [aes.BlockSize]byte, source io.Reader) (*DecryptStream, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	d := &DecryptStream{}

	// Init stream
	d.S = cipher.NewOFB(block, iv[:])

	// Set source
	d.R = source

	return d, nil
}
