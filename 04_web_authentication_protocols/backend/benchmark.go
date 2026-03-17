package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

func RunBenchmark(c *gin.Context) {

	message := []byte("authentication challenge")

	// -----------------------------
	// Symmetric Authentication Cost
	// HMAC-SHA256
	// -----------------------------

	secret := []byte("shared-secret-key")

	start := time.Now()

	for i := 0; i < 10000; i++ {

		mac := hmac.New(sha256.New, secret)
		mac.Write(message)
		_ = mac.Sum(nil)

	}

	symTime := time.Since(start)
	symAvg := symTime.Microseconds() / 10000

	AddLog(fmt.Sprintf("Symmetric Auth (HMAC-SHA256) Avg: %d µs", symAvg))

	// --------------------------------
	// Asymmetric Authentication Cost
	// ECDSA P-256 (WebAuthn equivalent)
	// --------------------------------

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	hash := sha256.Sum256(message)

	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hash[:])

	start = time.Now()

	for i := 0; i < 10000; i++ {

		ecdsa.Verify(
			&privateKey.PublicKey,
			hash[:],
			r,
			s,
		)

	}

	asymTime := time.Since(start)
	asymAvg := asymTime.Microseconds() / 10000

	AddLog(fmt.Sprintf("Asymmetric Auth (ECDSA-P256) Avg: %d µs", asymAvg))

	c.JSON(200, gin.H{
		"symmetric":  symAvg,
		"asymmetric": asymAvg,
	})
}