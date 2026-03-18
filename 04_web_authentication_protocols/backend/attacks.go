package main

import (
	"time"
	"encoding/base64"
	"fmt"

	"github.com/gin-gonic/gin"
)

func AttackNone(c *gin.Context) {

	AddLog("Creating forged token with alg=none")

	header := `{"alg":"none","typ":"JWT"}`
	payload := `{"username":"attacker","iat":0}`

	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))

	token := h + "." + p + "."

	AddLog("Forged token: " + token)

	if VerifySecureJWT(token) {
		AddLog("Secure verification accepted token")
	} else {
		AddLog("Secure verification rejected token")
	}

	if VerifyInsecureJWT(token) {
		AddLog("Vulnerable verification accepted token")
		AddLog("NONE algorithm attack successful")
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

	AddLog("Captured JWT token: " + token)

	for i := 1; i <= 3; i++ {

		ok := VerifySecureJWT(token)

		if ok {
			AddLog(fmt.Sprintf("Replay request %d → access granted", i))
		} else {
			AddLog(fmt.Sprintf("Replay request %d → access denied", i))
		}
	}

	AddLog("Replay protection not implemented")
	AddLog("Replay attack successful")

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

	var req struct {
		Token string `json:"token"`
	}

	c.BindJSON(&req)

	AddLog("Malicious script executed")
	AddLog("Token stolen from localStorage:")
	AddLog(req.Token)

	// Try secure verification
	if VerifySecureJWT(req.Token) {

		AddLog("Using stolen token to access protected resource")
		AddLog("Access granted")
		AddLog("Attacker successfully impersonated the user")

	} else {

		AddLog("Token invalid or expired")

		if VerifyInsecureJWT(req.Token) {
			AddLog("Vulnerable verification accepted token")
			AddLog("Attacker still able to impersonate user")
		}
	}

	AddLog("This attack works because JWT is stored in localStorage")
	AddLog("Mitigation: Use HttpOnly cookies instead")

	c.JSON(200, gin.H{"status": "xss executed"})
}