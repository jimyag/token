package token

import (
	"crypto/ed25519"
	"fmt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestPasetoPublicMaker(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	maker, err := NewPasetoPublicMaker(publicKey, privateKey)
	require.NoError(t, err)

	id := uuid.New()

	duration := time.Minute

	issuedAt := time.Now()

	expiredAt := issuedAt.Add(duration)

	payload := &Payload{
		ID:        id,
		IssuedAt:  issuedAt,
		ExpiredAt: expiredAt,
	}

	token, err := maker.CreateToken(payload)
	fmt.Println(token)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	payload, err = maker.VerifyToken(token)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	require.NotZero(t, payload.ID)
	require.Equal(t, id, payload.ID)
	require.WithinDuration(t, issuedAt, payload.IssuedAt, time.Second)
	require.WithinDuration(t, expiredAt, payload.ExpiredAt, time.Second)
}

func TestExpiredPasetoPublicToken(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	maker, err := NewPasetoPublicMaker(publicKey, privateKey)
	require.NoError(t, err)

	payload := &Payload{
		ID:        uuid.New(),
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(-time.Minute),
	}
	token, err := maker.CreateToken(payload)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	payload, err = maker.VerifyToken(token)
	require.Error(t, err)
	require.EqualError(t, err, ErrExpiredToken.Error())
	require.Nil(t, payload)
}
