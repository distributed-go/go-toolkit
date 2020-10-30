package jwtauth

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

type Role string

// AppClaims represent the claims parsed from JWT access token.
type AppClaims struct {
	ID    string `json:"ID,omitempty"`
	Sub   string `json:"Sub,omitempty"`
	Roles []Role `json:"Roles,omitempty"`
	jwt.StandardClaims
}

// ParseClaims parses JWT claims into AppClaims.
func (c *AppClaims) ParseClaims(claims jwt.MapClaims) error {
	// parse ID
	id, ok := claims["ID"]
	if !ok {
		return errors.New("could not parse claim id")
	}
	c.ID = id.(string)

	// parse Sub
	sub, ok := claims["Sub"]
	if !ok {
		return errors.New("could not parse claim sub")
	}
	c.Sub = sub.(string)

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
