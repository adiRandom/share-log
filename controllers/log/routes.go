package log

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers/base"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/dto"
	"shareLog/services"
)

type logController struct {
	base.BaseController
	logService services.Logger
}

type LogController interface {
	base.LoadableController
	LoadController(engine *gin.Engine)
}

type LogControllerProvider struct {
}

func (l LogControllerProvider) Provide() any {
	logService := di.Get[services.Logger]()
	baseController := di.Get[base.BaseController]()
	var instance LogController = &logController{
		baseController,
		logService,
	}
	return instance
}

func (l *logController) LoadController(engine *gin.Engine) {
	group := engine.Group("/log")
	//l.WithAuth(group)
	group.POST("/", l.createLog)
}

func (l *logController) createLog(c *gin.Context) {
	var logDto dto.Log
	err := c.BindJSON(&logDto)
	if err != nil {
		c.JSON(400, models.GetResponse(dto.Error{
			Code:    400,
			Message: err.Error()}))
		return
	}

	_, err = l.logService.SaveLog(logDto)
	if err != nil {
		c.JSON(500, models.GetResponse(dto.Error{
			Code:    500,
			Message: err.Error()}))
		return
	}

	c.Status(200)
}
