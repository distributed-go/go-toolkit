package jwtauth

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func TestAppClaims_ParseClaims(t *testing.T) {
	type fields struct {
		UserID         string
		Name           string
		Roles          []Role
		Type           string
		Metadata       map[string]interface{}
		Provider       string
		StandardClaims jwt.StandardClaims
	}
	type args struct {
		claims jwt.MapClaims
	}
	var userRole Role = "USER"
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Happy Path",
			args: args{
				claims: jwt.MapClaims{
					"uid":   "123456",
					"name":  "Mike",
					"roles": []Role{userRole},
					"type":  "Subscription",
					"metadata": map[string]interface{}{
						"userAgent": "Firefox",
					},
					"aud": "",
					"exp": (time.Now().UTC().Unix() + 60),
					"iat": time.Now().UTC().Unix(),
					"jti": "4564-bgf5456-bgf4b564b5fg-454b65gfb",
					"iss": "OAuth",
					"nbf": time.Now().UTC().Unix(),
					"sub": "JWT Authentication Token",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &AppClaims{
				UserID:         tt.fields.UserID,
				Name:           tt.fields.Name,
				Roles:          tt.fields.Roles,
				Type:           tt.fields.Type,
				Metadata:       tt.fields.Metadata,
				StandardClaims: tt.fields.StandardClaims,
			}
			if err := c.ParseClaims(tt.args.claims); (err != nil) != tt.wantErr {
				t.Errorf("AppClaims.ParseClaims() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
