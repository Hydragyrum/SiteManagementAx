package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const tokenSaltSize = 16

func deriveAES256Key(passphrase string, salt []byte) ([]byte, error) {
	if strings.TrimSpace(passphrase) == "" {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}
	return pbkdf2.Key(sha256.New, passphrase, salt, 600000, 32)
}

func newTokenGCM(passphrase string, salt []byte) (cipher.AEAD, error) {
	key, err := deriveAES256Key(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize gcm: %w", err)
	}
	return gcm, nil
}

func encryptTokenWithPassAndSalt(passphrase string, token string) (string, error) {
	if strings.TrimSpace(passphrase) == "" {
		return "", fmt.Errorf("token encryption passphrase is not configured")
	}

	salt := make([]byte, tokenSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	gcm, err := newTokenGCM(passphrase, salt)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(token), nil)
	payload := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	return base64.StdEncoding.EncodeToString(payload), nil
}

func decryptTokenWithPassAndSalt(passphrase string, encoded string) (string, error) {
	if strings.TrimSpace(passphrase) == "" {
		return "", fmt.Errorf("token encryption passphrase is not configured")
	}

	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid encrypted token format: %w", err)
	}
	if len(payload) <= tokenSaltSize {
		return "", fmt.Errorf("encrypted token payload is too short")
	}

	salt := payload[:tokenSaltSize]
	gcm, err := newTokenGCM(passphrase, salt)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(payload) <= tokenSaltSize+nonceSize {
		return "", fmt.Errorf("encrypted token payload is too short")
	}
	nonce := payload[tokenSaltSize : tokenSaltSize+nonceSize]
	ciphertext := payload[tokenSaltSize+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt token")
	}
	return string(plaintext), nil
}
