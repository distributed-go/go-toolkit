package jwtauth

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

// Role defines a perticular user role
type Role string

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
	// Provider of the account, e.g. oauth
	Provider string `json:"provider,omitempty"`
	// https://tools.ietf.org/html/rfc7519#section-4.1
	jwt.StandardClaims
}

// RefreshClaims represents the claims parsed from JWT refresh token.
type RefreshClaims struct {
	ID        string `json:"ID,omitempty"`
	TokenUUID string `json:"TokenUUID,omitempty"`
	jwt.StandardClaims
}

// ParseClaims parses JWT claims into AppClaims.
func (c *AppClaims) ParseClaims(claims jwt.MapClaims) error {
	// parse UserID
	id, ok := claims["UserID"]
	if !ok {
		return errors.New("could not parse user id")
	}
	c.UserID = id.(string)

	// parse Roles
	rl, ok := claims["Roles"]
	if !ok {
		return errors.New("could not parse claims roles")
	}
	var roles []Role
	if rl != nil {
		for _, v := range rl.([]interface{}) {
			r := v.(string)
			roles = append(roles, Role(r))
		}
	}
	c.Roles = roles

	return nil
}

// ParseClaims parses the JWT claims into RefreshClaims.
func (c *RefreshClaims) ParseClaims(claims jwt.MapClaims) error {
	// parse ID
	id, ok := claims["ID"]
	if !ok {
		return errors.New("could not parse claim id")
	}
	c.ID = id.(string)

	// parse Token
	token, ok := claims["TokenUUID"]
	if !ok {
		return errors.New("could not parse token uuid")
	}
	c.TokenUUID = token.(string)
	return nil
}
