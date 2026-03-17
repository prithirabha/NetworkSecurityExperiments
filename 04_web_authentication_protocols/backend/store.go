package main

var Users map[string]string
var Logs []string

func InitStore() {

	Users = map[string]string{
		"user": "password",
	}

	Logs = []string{}
}

func TrySecret(token string, secret string) bool {

	if secret == "12345" {
		return true
	}

	return false
}