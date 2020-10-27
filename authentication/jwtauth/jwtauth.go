package jwtauth

import (
	jwt "github.com/dgrijalva/jwt-go"
)

type jwtAuth struct {
	signKey   interface{}
	verifyKey interface{}
	signer    jwt.SigningMethod
	parser    *jwt.Parser
}

// NewJWTAuth creates a JWTAuth authenticator instance that provides middleware handlers
// and encoding/decoding functions for JWT signing.
// *jwt.Parser is custom parser settings introduced in jwt-go/v2.4.0.
func NewJWTAuth(alg string, parser *jwt.Parser, signKey interface{}, verifyKey interface{}) JWTAuth {
	return &jwtAuth{
		signKey:   signKey,
		verifyKey: verifyKey,
		signer:    jwt.GetSigningMethod(alg),
		parser:    parser,
	}
}
