package aead

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEADCrypter is an abstract implementation of the Crypterer interface using an arbitrary AEAD cipher.
type AEADCrypter struct {
	keys []cipher.AEAD
}

type AEADOption func(crypter *AEADCrypter) error

func NewAEADCrypter(options ...AEADOption) (*AEADCrypter, error) {
	var crypter AEADCrypter

	for _, option := range options {
		if err := option(&crypter); err != nil {
			return nil, err
		}
	}

	return &crypter, nil
}

func WithAESGCM(key []byte) AEADOption {
	return func(crypter *AEADCrypter) error {
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}

		crypter.keys = append(crypter.keys, aead)
		return nil
	}
}

func WithChaCha20(key []byte) AEADOption {
	return func(crypter *AEADCrypter) error {
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return err
		}
	
		crypter.keys = append(crypter.keys, aead)
		return nil
	}
}

func WithKey(key []byte) AEADOption {
	return func(crypter *AEADCrypter) error {
		aead, err := crypter.constructor(key)
		if err != nil {
			return err
		}
		crypter.keys = append(crypter.keys, aead)
		return nil
	}
}
