package token

import (
	"crypto/ed25519"
)

type MyPublicPayload struct {
	Payload
	Username string
}

type MyPublicToken struct {
	PasetoPublicMaker
}

func NewMyPublicMaker(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (Maker, error) {
	return NewPasetoPublicMaker(publicKey, privateKey)
}

// CreateToken creates a new token for a specific username and duration
func (maker *MyPublicToken) CreateToken(payload *Payload, opt ...interface{}) (string, error) {
	return maker.paseto.Sign(maker.privateKey, payload, opt)
}

// VerifyToken checks if the token is valid or not
func (maker *MyPublicToken) VerifyToken(token string) (*Payload, error) {
	return maker.VerifyToken(token)
}
