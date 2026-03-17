package main

import (
	"time"

	"github.com/gin-gonic/gin"
)

func AttackNone(c *gin.Context) {

	AddLog("Forged token created with alg=none")

	token := "eyJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6InVzZXIifQ."

	if VerifySecureJWT(token) {
		AddLog("Secure verification accepted")
	} else {
		AddLog("Secure verification rejected")
	}

	if VerifyInsecureJWT(token) {
		AddLog("Vulnerable verification accepted")
		AddLog("Attack successful")
	}

	c.JSON(200, gin.H{"status": "none attack executed"})
}

func AttackBruteforce(c *gin.Context) {

	dict := []string{"password", "admin", "secret", "12345", "jwtsecret"}

	token, _ := GenerateSecureJWT("user")

	for _, s := range dict {

		AddLog("Trying " + s)

		if TrySecret(token, s) {
			AddLog("Secret key discovered: " + s)
			break
		}
	}

	c.JSON(200, gin.H{"status": "bruteforce completed"})
}

func AttackReplay(c *gin.Context) {

	token, _ := GenerateSecureJWT("user")

	AddLog("Captured JWT token")

	for i := 1; i <= 3; i++ {

		if VerifySecureJWT(token) {
			AddLog("Replay request success")
		}
	}

	AddLog("Replay protection not implemented")
	AddLog("Attack successful")

	c.JSON(200, gin.H{"status": "replay executed"})
}

func AttackExpired(c *gin.Context) {

	token, _ := GenerateSecureJWT("user")

	AddLog("Token generated")
	AddLog("Waiting for expiration")

	time.Sleep(11 * time.Second)

	AddLog("Token expired")

	if !VerifySecureJWT(token) {
		AddLog("Secure verification rejected token")
	}

	if VerifyInsecureJWT(token) {
		AddLog("Vulnerable verification accepted expired token")
		AddLog("Attack successful")
	}

	c.JSON(200, gin.H{"status": "expired attack executed"})
}

func AttackXSS(c *gin.Context) {

	AddLog("Executing malicious script")
	AddLog("localStorage.getItem('token')")
	AddLog("JWT token stolen")
	AddLog("Attacker can impersonate user")

	c.JSON(200, gin.H{"status": "xss executed"})
}