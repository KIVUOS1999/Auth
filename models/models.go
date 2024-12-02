package models

import "github.com/golang-jwt/jwt"

type TokenRequest struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	Scope     string `json:"scope"`
	GrantType string `json:"grant_type"`
	Audience  string `json:"audience"`
}

type TokenResponse struct {
	Auth    string `json:"auth_token"`
	Refresh string `json:"refresh_token"`
}

type Claims struct {
	GrantType string `json:"grant_type"`
	Scope     string `json:"scope"`
	jwt.StandardClaims
}

type CustomError struct {
	Reason string `json:"reason"`
}

type ValidateRequest struct {
	Auth string `json:"auth_token"`
}
