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

// simulate a stored credential (like WebAuthn public key)
var storedPrivateKey *ecdsa.PrivateKey
var storedPublicKey *ecdsa.PublicKey

func init() {
	// generate once → acts like "registered device"
	storedPrivateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	storedPublicKey = &storedPrivateKey.PublicKey
}

func RunBenchmark(c *gin.Context) {

	message := []byte("authentication challenge")

	// -----------------------------
	// Symmetric Authentication
	// -----------------------------

	secret := []byte("shared-secret-key")

	// precompute expected MAC
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	start := time.Now()

	for i := 0; i < 100000; i++ {

		m := hmac.New(sha256.New, secret)
		m.Write(message)
		actual := m.Sum(nil)

		hmac.Equal(expectedMAC, actual)
	}

	symTime := time.Since(start)
	symAvg := symTime.Nanoseconds() / 100000

	AddLog(fmt.Sprintf(
		"Symmetric Auth (HMAC-SHA256) Avg: %.2f µs (%.6f ms)",
		float64(symAvg)/1000,
		float64(symAvg)/1_000_000,
	))

	// --------------------------------
	// Asymmetric Authentication
	// --------------------------------

	// simulate challenge hash
	hash := sha256.Sum256(message)

	// simulate authenticator signing (once)
	r, s, _ := ecdsa.Sign(rand.Reader, storedPrivateKey, hash[:])

	start = time.Now()

	for i := 0; i < 100000; i++ {

		ecdsa.Verify(
			storedPublicKey,
			hash[:],
			r,
			s,
		)
	}

	asymTime := time.Since(start)
	asymAvg := asymTime.Nanoseconds() / 100000

	AddLog(fmt.Sprintf(
		"Asymmetric Auth (ECDSA-P256) Avg: %.2f µs (%.6f ms)",
		float64(asymAvg)/1000,
		float64(asymAvg)/1_000_000,
	))

	// convert to µs for readability
	symUS := float64(symAvg) / 1000
	asymUS := float64(asymAvg) / 1000

	// ratio (how many times slower)
	ratio := asymUS / symUS

	// percentage difference
	percent := (ratio - 1) * 100

	AddLog(fmt.Sprintf(
		"Symmetric Auth (HMAC-SHA256): %.2f µs (%.6f ms)",
		symUS,
		symUS/1000,
	))

	AddLog(fmt.Sprintf(
		"Asymmetric Auth (ECDSA-P256): %.2f µs (%.6f ms)",
		asymUS,
		asymUS/1000,
	))

	AddLog(fmt.Sprintf(
		"Asymmetric is %.2fx slower (%.0f%% higher cost)",
		ratio,
		percent,
	))

	c.JSON(200, gin.H{
		"symmetric_us":  float64(symAvg) / 1000,
		"symmetric_ms":  float64(symAvg) / 1_000_000,
		"asymmetric_us": float64(asymAvg) / 1000,
		"asymmetric_ms": float64(asymAvg) / 1_000_000,
		"ratio":         ratio,
		"percent":       percent,
	})
}