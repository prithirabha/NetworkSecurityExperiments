package main

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

var webUser User

var webAuthn *webauthn.WebAuthn

// ---- LOG STORAGE ----
var Logs []string

// ---- INIT STORE ----
func InitStore() {

	webUser = User{
		ID:          []byte("1001"),
		Name:        "user",
		DisplayName: "SecurityLabUser",
		Credentials: []webauthn.Credential{},
	}

	Logs = []string{}
}

// ---- WEB AUTHN INTERFACE ----
func (u User) WebAuthnID() []byte {
	return u.ID
}

func (u User) WebAuthnName() string {
	return u.Name
}

func (u User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u User) WebAuthnIcon() string {
	return ""
}

func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// ---- BRUTE FORCE SECRET TEST ----
func TrySecret(tokenString string, secret string) bool {

	_, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	return err == nil
}