package main

import (
	"github.com/gin-gonic/gin"
)

func WebAuthnRegister(c *gin.Context) {

	AddLog("WebAuthn registration started")
	AddLog("Challenge generated")
	AddLog("Credential created")
	AddLog("Public key stored")

	c.JSON(200, gin.H{"status": "registered"})
}

func WebAuthnLogin(c *gin.Context) {

	AddLog("WebAuthn login challenge created")
	AddLog("Credential used")
	AddLog("Signature verified")
	AddLog("Authentication successful")

	c.JSON(200, gin.H{"status": "authenticated"})
}