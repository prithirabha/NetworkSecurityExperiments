package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Login(c *gin.Context) {

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	c.BindJSON(&req)

	if req.Username == "user" && req.Password == "password" {

		token, _ := GenerateSecureJWT(req.Username)

		AddLog("User login successful")
		AddLog("JWT issued")

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