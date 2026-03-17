package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("12345")

func GenerateJWT(username string) (string, error) {

	claims := jwt.MapClaims{
		"username": username,
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(10 * time.Second).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(jwtSecret)
}

func VerifyJWT(tokenString string, secure bool) bool {

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})

	if err != nil {
		return false
	}

	if token.Method.Alg() == "none" && secure {
		return false
	}

	parsed, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return false
	}

	if claims, ok := parsed.Claims.(jwt.MapClaims); ok {

		if secure {

			exp := int64(claims["exp"].(float64))

			if time.Now().Unix() > exp {
				return false
			}
		}

		return true
	}

	return false
}