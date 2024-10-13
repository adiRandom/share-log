package main

import (
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"os"
	"shareLog/controllers"
	"shareLog/di/providers"
)

const shouldLoadLocalEnvArgIndex = 1

func loadLocalEnv() {
	if os.Args[shouldLoadLocalEnvArgIndex] == "true" {
		godotenv.Load(".env")
	}
}

func main() {
	loadLocalEnv()
	providers.InitDi()
	engine := gin.Default()
	controllers.LoadAllController(engine)
	engine.Run()
}
