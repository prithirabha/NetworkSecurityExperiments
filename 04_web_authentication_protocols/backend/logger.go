package main

import "github.com/gin-gonic/gin"

func InitLogger() {}

func AddLog(msg string) {

	Logs = append(Logs, msg)
}

func GetLogs(c *gin.Context) {

	c.JSON(200, Logs)
}