package token

import (
	"github.com/google/uuid"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	key = "sdfsfdffddsdjfisajdfasjdfamdksss"
)

func TestPasetoMaker(t *testing.T) {
	maker, err := NewPasetoMaker(key)
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

func TestExpiredPasetoToken(t *testing.T) {
	maker, err := NewPasetoMaker(key)
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