package controllers

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers/log"
	"shareLog/di"
)

func LoadAllController(engine *gin.Engine) {
	logController := di.Get[log.LogController]()
	logController.LoadLogController(engine)

}
