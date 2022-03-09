package token

type MyLocalPayload struct {
	Payload
	Username string
}

type MyLocalToken struct {
	PasetoMaker
}

func NewMyLocalMaker(symmetricKey string) (Maker, error) {
	return NewPasetoMaker(symmetricKey)
}

// CreateToken creates a new token for a specific username and duration
func (maker *MyLocalToken) CreateToken(payload Payloads, opt ...interface{}) (string, error) {
	return maker.paseto.Encrypt(maker.symmetricKey, payload, opt)
}

// VerifyToken checks if the token is valid or not
func (maker *MyLocalToken) VerifyToken(token string) (*Payload, error) {
	return maker.VerifyToken(token)
}
