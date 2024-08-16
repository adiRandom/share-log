package main

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/di/providers"
)

func main() {
	providers.InitDi()

	engine := gin.Default()

	// Test code
	di.Get[repository.KeyRepository]().CreateDefaultKeys()
	di.Get[repository.UserRepository]().CreateDefaultUser()

	controllers.LoadAllController(engine)

	engine.Run()
}
