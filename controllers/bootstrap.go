package controllers

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers/base"
	"shareLog/di"
)

func LoadAllController(engine *gin.Engine) {
	controllers := di.GetAll[base.LoadableController]()
	for _, controller := range controllers {
		controller.LoadController(engine)
	}
}
