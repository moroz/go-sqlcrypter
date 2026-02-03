package aead

import (
	"testing"

	"github.com/bincyber/go-sqlcrypter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAEADCrypter(t *testing.T) {
	t.Run("AES-GCM-256 with one key", func(t *testing.T) {
		key, err := sqlcrypter.GenerateBytes(32)
		require.NoError(t, err)

		crypter, err := NewAEADCrypter(WithAESGCM(), WithKey(key))
		assert.NoError(t, err)
		assert.Equal(t, 1, len(crypter.keys))
	})

	t.Run("AES-GCM-256 with multiple keys", func(t *testing.T) {
		key1, err := sqlcrypter.GenerateBytes(32)
		require.NoError(t, err)
		key2, err := sqlcrypter.GenerateBytes(32)
		require.NoError(t, err)

		crypter, err := NewAEADCrypter(WithAESGCM(), WithKey(key1), WithKey(key2))
		assert.NoError(t, err)
		assert.Equal(t, 2, len(crypter.keys))
	})

	t.Run("ChaCha20 with one key", func(t *testing.T) {
		key, err := sqlcrypter.GenerateBytes(32)
		require.NoError(t, err)

		crypter, err := NewAEADCrypter(WithChaCha20(), WithKey(key))
		assert.NoError(t, err)
		assert.Equal(t, 1, len(crypter.keys))
	})
}
