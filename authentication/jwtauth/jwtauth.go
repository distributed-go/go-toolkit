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

// GenTokenPair returns both an access token and a refresh token.
func (ja *jwtAuth) GenTokenPair(accessClaims *AppClaims, refreshClaims *RefreshClaims) (string, string, error) {
	access, err := ja.CreateJWT(accessClaims)
	if err != nil {
		return "", "", err
	}
	refresh, err := ja.CreateRefreshJWT(refreshClaims)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

// CreateJWT returns an access token for provided account claims.
func (ja *jwtAuth) CreateJWT(c *AppClaims) (string, error) {
	c.IssuedAt = time.Now().Unix()
	c.ExpiresAt = time.Now().Add(ja.jwtExpiry).Unix()
	_, tokenString, err := ja.Encode(c)
	return tokenString, err
}

// CreateRefreshJWT returns a refresh token for provided token Claims.
func (ja *jwtAuth) CreateRefreshJWT(c *RefreshClaims) (string, error) {
	c.IssuedAt = time.Now().Unix()
	c.ExpiresAt = time.Now().Add(ja.jwtExpiry).Unix()
	_, tokenString, err := ja.Encode(c)
	return tokenString, err
}
