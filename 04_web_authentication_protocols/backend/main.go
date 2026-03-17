package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {

	InitStore()
	InitLogger()
	InitWebAuthn()

	r := gin.Default()

	r.Static("/static", "./frontend/static")
	r.LoadHTMLGlob("frontend/templates/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", nil)
	})

	r.POST("/login", Login)

	r.GET("/protected/secure", ProtectedSecure)
	r.GET("/protected/insecure", ProtectedInsecure)

	r.POST("/webauthn/register", WebAuthnRegister)
	r.POST("/webauthn/register/finish", WebAuthnRegisterFinish)

	r.POST("/webauthn/login", WebAuthnLogin)
	r.POST("/webauthn/login/finish", WebAuthnLoginFinish)

	r.POST("/attack/none", AttackNone)
	r.POST("/attack/bruteforce", AttackBruteforce)
	r.POST("/attack/replay", AttackReplay)
	r.POST("/attack/expired", AttackExpired)
	r.POST("/attack/xss", AttackXSS)

	r.GET("/benchmark", RunBenchmark)

	r.GET("/logs", GetLogs)

	log.Println("Server running on :8080")
	r.Run(":8080")
}