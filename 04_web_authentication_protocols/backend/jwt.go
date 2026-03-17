package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("12345")

func GenerateSecureJWT(username string) (string, error) {

	claims := jwt.MapClaims{
		"username": username,
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(10 * time.Second).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(jwtSecret)
}

func GenerateInsecureJWT(username string) (string, error) {

	claims := jwt.MapClaims{
		"username": username,
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(10 * time.Second).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(jwtSecret)
}

func VerifySecureJWT(tokenString string) bool {

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {

		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, jwt.ErrSignatureInvalid
		}

		return jwtSecret, nil
	})

	if err != nil {
		return false
	}

	claims := token.Claims.(jwt.MapClaims)

	exp := int64(claims["exp"].(float64))

	if time.Now().Unix() > exp {
		return false
	}

	return token.Valid
}

func VerifyInsecureJWT(tokenString string) bool {

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})

	if err != nil {
		return false
	}

	// accepts alg=none and skips expiration
	if token != nil {
		return true
	}

	return false
}