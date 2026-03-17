package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func LoginHandler(c *gin.Context) {

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	c.BindJSON(&req)

	if req.Username == "user" && req.Password == "password" {

		token, _ := GenerateJWT(req.Username)

		AddLog("User logged in successfully")

		c.JSON(200, gin.H{
			"token": token,
		})

		return
	}

	AddLog("Login failed")

	c.JSON(http.StatusUnauthorized, gin.H{
		"error": "invalid credentials",
	})
}

func ProtectedHandler(c *gin.Context) {

	token := c.GetHeader("Authorization")

	valid := VerifyJWT(token, true)

	if !valid {
		AddLog("Protected endpoint access denied")
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	AddLog("Protected endpoint accessed")

	c.JSON(200, gin.H{
		"message": "protected data",
	})
}	