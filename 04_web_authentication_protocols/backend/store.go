package main

import "github.com/golang-jwt/jwt/v5"

var Users map[string]string
var Logs []string

func InitStore() {

	Users = map[string]string{
		"user": "password",
	}

	Logs = []string{}
}

func TrySecret(tokenString string, secret string) bool {

	_, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err == nil {
		return true
	}

	return false
}