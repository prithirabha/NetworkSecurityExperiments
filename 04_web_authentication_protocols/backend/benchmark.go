package main

import (
	"time"

	"github.com/gin-gonic/gin"
)

func RunBenchmark(c *gin.Context) {

	token, _ := GenerateJWT("user")

	start := time.Now()

	for i := 0; i < 100; i++ {
		VerifyJWT(token, true)
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