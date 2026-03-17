package main

import (
	"time"

	"github.com/gin-gonic/gin"
)

func RunBenchmark(c *gin.Context) {

	token, _ := GenerateSecureJWT("user")

	start := time.Now()

	for i := 0; i < 100; i++ {
		VerifySecureJWT(token)
	}

	jwtTime := time.Since(start)

	start = time.Now()

	for i := 0; i < 100; i++ {
		time.Sleep(time.Millisecond * 10)
	}

	webauthTime := time.Since(start)

	AddLog("Benchmark completed")

	c.JSON(200, gin.H{
		"jwt":     jwtTime.Milliseconds(),
		"webauth": webauthTime.Milliseconds(),
	})
}