package jwtauth

import (
	"context"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

// JWTAuth implements the JWTAuth methods
type JWTAuth interface {
	// Functions to extract tokens from http request
	TokenFromCookie(r *http.Request) string
	TokenFromHeader(r *http.Request) string
	TokenFromQuery(r *http.Request) string

	// Functions to encode and decode tokens
	Encode(claims jwt.Claims) (t *jwt.Token, tokenString string, err error)
	Decode(tokenString string) (t *jwt.Token, err error)

	// Functions to work with context
	TokenFromContext(ctx context.Context) (*jwt.Token, jwt.MapClaims, error)
	NewContext(ctx context.Context, t *jwt.Token, err error) context.Context
}
