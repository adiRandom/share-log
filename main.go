package main

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers"
	"shareLog/di/providers"
)

func main() {
	providers.InitDi()
	engine := gin.Default()
	controllers.LoadAllController(engine)
	engine.Run()
}
