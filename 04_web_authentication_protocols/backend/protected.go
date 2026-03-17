package main

import (
	"github.com/gin-gonic/gin"
)

func ProtectedSecure(c *gin.Context) {

	token := c.GetHeader("Authorization")

	if !VerifySecureJWT(token) {
		AddLog("Secure endpoint rejected token")
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	AddLog("Secure endpoint access granted")

	c.JSON(200, gin.H{
		"message": "secure endpoint data",
	})
}

func ProtectedInsecure(c *gin.Context) {

	token := c.GetHeader("Authorization")

	if !VerifyInsecureJWT(token) {
		AddLog("Insecure endpoint rejected token")
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	AddLog("Insecure endpoint accepted token")

	c.JSON(200, gin.H{
		"message": "insecure endpoint data",
	})
}