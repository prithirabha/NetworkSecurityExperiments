package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
)

var sessionData *webauthn.SessionData

func InitWebAuthn() {

	config := &webauthn.Config{
		RPDisplayName: "Auth Security Lab",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	}

	webAuthn, _ = webauthn.New(config)
}

func WebAuthnRegister(c *gin.Context) {

	AddLog("WebAuthn registration started")

	options, session, err := webAuthn.BeginRegistration(&webUser)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	sessionData = session

	c.JSON(200, options)
}

func WebAuthnRegisterFinish(c *gin.Context) {

	cred, err := webAuthn.FinishRegistration(&webUser, *sessionData, c.Request)

	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	webUser.Credentials = append(webUser.Credentials, *cred)

	AddLog("WebAuthn credential registered")

	c.JSON(200, gin.H{"status": "registered"})
}

func WebAuthnLogin(c *gin.Context) {

	options, session, err := webAuthn.BeginLogin(&webUser)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	sessionData = session

	AddLog("WebAuthn login challenge created")

	c.JSON(200, options)
}

func WebAuthnLoginFinish(c *gin.Context) {

	_, err := webAuthn.FinishLogin(&webUser, *sessionData, c.Request)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		return
	}

	AddLog("WebAuthn authentication successful")

	c.JSON(200, gin.H{"status": "authenticated"})
}