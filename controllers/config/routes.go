package config

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers/base"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/dto"
)

type configController struct {
	base.BaseController
	userRepo repository.UserRepository
}

type Controller interface {
	base.LoadableController
}

type ControllerProvider struct {
}

func (a ControllerProvider) Provide() any {
	baseController := di.Get[base.BaseController]()
	userRepo := di.Get[repository.UserRepository]()

	instance := configController{
		baseController,
		userRepo,
	}

	return &instance
}

func (a *configController) LoadController(engine *gin.Engine) {
	config := engine.Group("/config")
	{
		config.GET("/init-signup", a.canDoInitSignup)
	}
}

func (a *configController) canDoInitSignup(c *gin.Context) {
	userCount, err := a.userRepo.Count()
	if err != nil {
		c.JSON(500, models.GetResponse(nil,
			&dto.Error{Code: 500, Message: err.Error()},
		))
	}

	if userCount != 0 {
		c.Status(403)
		return
	}

	c.Status(200)
}
