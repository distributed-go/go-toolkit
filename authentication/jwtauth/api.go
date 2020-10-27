package jwtauth

import (
	"context"

	jwt "github.com/dgrijalva/jwt-go"
)

// JWTAuth implements the JWTAuth methods
type JWTAuth interface {
	// Functions to work with context
	TokenFromContext(ctx context.Context) (*jwt.Token, jwt.MapClaims, error)
	NewContext(ctx context.Context, t *jwt.Token, err error) context.Context
}
