package token

import (
	"crypto/ed25519"
	"github.com/google/uuid"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMyPublicMaker(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	maker, err := NewMyPublicMaker(publicKey, privateKey)
	require.NoError(t, err)

	id := uuid.New()

	duration := time.Minute

	issuedAt := time.Now()

	expiredAt := issuedAt.Add(duration)

	payload := &MyPublicPayload{
		Payload: Payload{
			ID:        id,
			IssuedAt:  issuedAt,
			ExpiredAt: expiredAt,
		},
		Username: "sssss",
	}

	token, err := maker.CreateToken(payload)

	require.NoError(t, err)
	require.NotEmpty(t, token)

	payloads, erro := maker.VerifyToken(token)
	require.NoError(t, erro)
	require.NotEmpty(t, token)

	require.NotZero(t, payloads.ID)
	require.Equal(t, id, payloads.ID)
	require.WithinDuration(t, issuedAt, payloads.IssuedAt, time.Second)
	require.WithinDuration(t, expiredAt, payloads.ExpiredAt, time.Second)
}

func TestExpiredMyPublicToken(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	maker, err := NewMyPublicMaker(publicKey, privateKey)
	require.NoError(t, err)
	payload := &MyPublicPayload{
		Payload: Payload{
			ID:        uuid.New(),
			IssuedAt:  time.Now(),
			ExpiredAt: time.Now().Add(-time.Minute),
		},
		Username: "sssss",
	}
	token, err := maker.CreateToken(payload)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	payloads, erro := maker.VerifyToken(token)
	require.Error(t, erro)
	require.EqualError(t, erro, ErrExpiredToken.Error())
	require.Nil(t, payloads)
}
