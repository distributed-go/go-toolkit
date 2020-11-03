package jwtauth

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type jwtAuth struct {
	signKey          interface{}
	verifyKey        interface{}
	signer           jwt.SigningMethod
	parser           *jwt.Parser
	jwtExpiry        time.Duration
	jwtRefreshExpiry time.Duration
}

// NewJWTAuth creates a JWTAuth authenticator instance that provides middleware handlers
// and encoding/decoding functions for JWT signing.
// *jwt.Parser is custom parser settings introduced in jwt-go/v2.4.0.
func NewJWTAuth(config Config) JWTAuth {
	return &jwtAuth{
		signKey:          config.SignKey,
		verifyKey:        config.VerifyKey,
		signer:           jwt.GetSigningMethod(config.JwtAuthAlgo),
		parser:           config.JwtParser,
		jwtExpiry:        config.JwtExpiry,
		jwtRefreshExpiry: config.JwtRefreshExpiry,
	}
}
