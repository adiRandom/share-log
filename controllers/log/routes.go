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

	l.WithAuth(group)
	{
		group.POST("/", l.createLog)
		group.GET("/:id", l.getLog)

		// TODO: Delete
		group.POST("/test/", l.createLogFromPlain)
	}
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

	c.Status(201)
}

func (l *logController) getLog(c *gin.Context) {
	logId, err := l.GetUIntParam(c, "id")
	if err != nil {
		return
	}

	user := l.GetUser(c)
	if user == nil {
		c.Status(401)
		return
	}

	hasAccess, err := l.logService.HaveAccessToLog(logId, user)
	if !hasAccess {
		c.Status(403)
		return
	}

	userSymmetricKey := l.GetUserSymmetricKey(c)
	decryptedLog, err := l.logService.GetDecryptedLog(logId, user, userSymmetricKey)
	if err != nil {
		c.JSON(500, models.GetResponse(dto.Error{
			Code:    500,
			Message: err.Error(),
		}))
		return
	}

	c.JSON(200, models.GetResponse(dto.DecryptedLog{
		StackTrace: decryptedLog.StackTrace,
	}))
}

func (l *logController) createLogFromPlain(c *gin.Context) {
	var logDto dto.Log
	err := c.BindJSON(&logDto)
	if err != nil {
		c.JSON(400, models.GetResponse(dto.Error{
			Code:    400,
			Message: err.Error()}))
		return
	}

	l.logService.SavePlainLog(logDto)

	c.Status(201)
}
