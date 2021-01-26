package authentication

import (
	"errors"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// Role defines a perticular user role
type Role string

// Library errors
var (
	ErrUnauthorized = errors.New("authentication: token is unauthorized")
	ErrExpired      = errors.New("authentication: token is expired")
	ErrNBFInvalid   = errors.New("authentication: token nbf validation failed")
	ErrIATInvalid   = errors.New("authentication: token iat validation failed")
	ErrNoTokenFound = errors.New("authentication: no token found")
	ErrAlgoInvalid  = errors.New("authentication: algorithm mismatch")
)

// JWTAuth implements the JWTAuth methods
type JWTAuth interface {
	// Functions to create JWTs
	GenTokenPair(accessClaims *AppClaims, refreshClaims *RefreshClaims) (string, string, error)
	CreateJWT(c *AppClaims) (string, error)
	CreateRefreshJWT(c *RefreshClaims) (string, error)

	// Middlewares for validating JWT tokens
	Authenticate(next http.Handler) http.Handler
	Verify() func(http.Handler) http.Handler
	RequiresRole(role Role) func(next http.Handler) http.Handler

	// Functions to extract tokens from http request
	TokenFromCookie(r *http.Request) string
	TokenFromHeader(r *http.Request) string
	TokenFromQuery(r *http.Request) string

	// Functions to encode and decode tokens
	Encode(claims jwt.Claims) (t *jwt.Token, tokenString string, err error)
	Decode(tokenString string) (t *jwt.Token, err error)

	// Utility functions for setting token expiry
	ExpireIn(tm time.Duration) int64
	SetIssuedAt(claims jwt.MapClaims, tm time.Time)
	SetIssuedNow(claims jwt.MapClaims)
	SetExpiry(claims jwt.MapClaims, tm time.Time)
	SetExpiryIn(claims jwt.MapClaims, tm time.Duration)
}

// Config holds the configuration for the jwtauth
type Config struct {
	// Algorithm to be used for for signing and validating JWT token
	JwtAuthAlgo string `json:"jwtAuthAlgo"`
	// JWT token expiry duration
	JwtExpiry time.Duration `json:"jwtExpiry"`
	// Refresh token expiry duration
	JwtRefreshExpiry time.Duration `json:"jwtRefreshExpiry"`
	// Private key used for generating JWT token
	SignKey interface{} `json:"signKey"`
	// Public key used to validate the JWT token
	VerifyKey interface{} `json:"verifyKey"`
	// Custom JWT Parser *jwt.Parser is custom parser settings introduced in jwt-go/v2.4.0.
	JwtParser *jwt.Parser `json:"jwtParser"`
}

// AppClaims represent the claims parsed from JWT access token.
type AppClaims struct {
	// ID for the account
	UserID string `json:"uid,omitempty"`
	// Name of the account e.g. an email or username
	Name string `json:"name,omitempty"`
	// Roles the account has access too
	Roles []Role `json:"roles,omitempty"`
	// Type of the account, e.g. user
	Type string `json:"type,omitempty"`
	// Metadata associated with the account
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// https://tools.ietf.org/html/rfc7519#section-4.1
	jwt.StandardClaims
}

// RefreshClaims represents the claims parsed from JWT refresh token.
type RefreshClaims struct {
	// ID for the account
	UserID string `json:"uid,omitempty"`
	// Roles the account has access too
	Roles []Role `json:"roles,omitempty"`
	// Metadata associated with the account
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// https://tools.ietf.org/html/rfc7519#section-4.1
	jwt.StandardClaims
}
