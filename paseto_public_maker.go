package token

import (
	"crypto/ed25519"
	"fmt"
	"github.com/o1egl/paseto"
)

type PasetoPublicMaker struct {
	paseto     *paseto.V2
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewPasetoPublicMaker(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (Maker, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private size :must be exactly %d", ed25519.PrivateKeySize)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public size :must be exactly %d", ed25519.PublicKeySize)
	}

	maker := &PasetoPublicMaker{
		paseto:     paseto.NewV2(),
		privateKey: privateKey,
		publicKey:  publicKey,
	}
	return maker, nil
}

// CreateToken creates a new token for a specific username and duration
func (maker *PasetoPublicMaker) CreateToken(payload Payloads, opt ...interface{}) (string, error) {
	return maker.paseto.Sign(maker.privateKey, payload, opt)

}

// VerifyToken checks if the token is valid or not
func (maker *PasetoPublicMaker) VerifyToken(token string) (*Payload, error) {
	payload := &Payload{}
	err := maker.paseto.Verify(token, maker.publicKey, payload, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}
	return payload, nil
}
