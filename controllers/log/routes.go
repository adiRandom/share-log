package log

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/dto"
	"shareLog/services"
	"strconv"
)

type logController struct {
	controllers.BaseController
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
	baseController := di.Get[controllers.BaseController]()
	var instance LogController = &logController{
		baseController,
		logService,
	}
	return instance
}

func (l *logController) LoadLogController(engine *gin.Engine) {
	group := engine.Group("/log")
	l.WithAuth(group)
	group.POST("/", l.createLog)
	group.GET("/:id", l.getLogById)
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

const getLogIdParam = "id"

func (l *logController) getLogById(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param(getLogIdParam), 10, 32)
	if err != nil {
		c.Status(400)
	}

	user := l.GetUser(c)
	if user == nil {
		c.Status(401)
		return
	}

	userSymmetricKey := l.GetUserSymmetricKey(c)
	log, err := l.logService.GetLog(uint(id), user, userSymmetricKey)
	if err != nil {
		c.JSON(500, models.GetResponse(dto.Error{
			Code:    500,
			Message: err.Error()}))
		return
	}

	c.JSON(200, models.GetResponse(log))
}
