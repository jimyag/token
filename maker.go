package token

type Payloads interface {
	Valid() error
}

// Maker is an interface for managing tokens
type Maker interface {
	// CreateToken creates a new token for Payloads
	CreateToken(payload Payloads, opt ...interface{}) (string, error)

	// VerifyToken checks if the token is valid or not
	VerifyToken(token string) (*Payload, error)
}
