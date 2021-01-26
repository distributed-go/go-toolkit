package authentication

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

// ParseClaims parses JWT claims into AppClaims.
func (c *AppClaims) ParseClaims(claims jwt.MapClaims) error {
	// parse UserID
	id, ok := claims["uid"]
	if !ok {
		return errors.New("could not parse user id")
	}
	c.UserID = id.(string)

	// Parse name
	if name, ok := claims["name"]; ok {
		c.Name = name.(string)
	}

	// parse Roles
	rl, ok := claims["roles"]
	if !ok {
		return errors.New("could not parse claims roles")
	}
	var roles []Role
	if rl != nil {
		for _, v := range rl.([]Role) {
			roles = append(roles, v)
		}
	}
	c.Roles = roles

	// Parse Type
	if t, ok := claims["type"]; ok {
		c.Type = t.(string)
	}

	// Parse metadata
	if meta, ok := claims["metadata"]; ok {
		c.Metadata = meta.(map[string]interface{})
	}

	// Parse standars claims
	if aud, ok := claims["aud"]; ok {
		c.Audience = aud.(string)
	}
	if exp, ok := claims["exp"]; ok {
		c.ExpiresAt = exp.(int64)
	}
	if jti, ok := claims["jti"]; ok {
		c.Id = jti.(string)
	}
	if iat, ok := claims["iat"]; ok {
		c.IssuedAt = iat.(int64)
	}
	if iss, ok := claims["iss"]; ok {
		c.Issuer = iss.(string)
	}
	if nbf, ok := claims["nbf"]; ok {
		c.NotBefore = nbf.(int64)
	}
	if sub, ok := claims["sub"]; ok {
		c.Subject = sub.(string)
	}

	return nil
}

// ParseClaims parses the JWT claims into RefreshClaims.
func (c *RefreshClaims) ParseClaims(claims jwt.MapClaims) error {
	// parse UserID
	id, ok := claims["uid"]
	if !ok {
		return errors.New("could not parse user id")
	}
	c.UserID = id.(string)

	// parse Roles
	rl, ok := claims["roles"]
	if !ok {
		return errors.New("could not parse claims roles")
	}
	var roles []Role
	if rl != nil {
		for _, v := range rl.([]Role) {
			roles = append(roles, v)
		}
	}
	c.Roles = roles

	// Parse metadata
	if meta, ok := claims["metadata"]; ok {
		c.Metadata = meta.(map[string]interface{})
	}

	// Parse standars claims
	if aud, ok := claims["aud"]; ok {
		c.Audience = aud.(string)
	}
	if exp, ok := claims["exp"]; ok {
		c.ExpiresAt = exp.(int64)
	}
	if jti, ok := claims["jti"]; ok {
		c.Id = jti.(string)
	}
	if iat, ok := claims["iat"]; ok {
		c.ExpiresAt = iat.(int64)
	}
	if iss, ok := claims["iss"]; ok {
		c.Issuer = iss.(string)
	}
	if nbf, ok := claims["nbf"]; ok {
		c.ExpiresAt = nbf.(int64)
	}
	if sub, ok := claims["sub"]; ok {
		c.Subject = sub.(string)
	}

	return nil
}
