package log

import (
	"github.com/gin-gonic/gin"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/dto"
	"shareLog/services"
)

type logController struct {
	logService services.Logger
}

type LogController interface {
	LoadLogController(engine *gin.Engine)
	createLog(c *gin.Context)
}

type LogControllerProvider struct {
}

func (l LogControllerProvider) Provide() LogController {
	logService := di.Get[services.Logger]()
	var instance LogController = &logController{logService: logService}
	return instance
}

func (l *logController) LoadLogController(engine *gin.Engine) {
	group := engine.Group("/log")
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
