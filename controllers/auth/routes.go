package auth

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers/base"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/dto"
	"shareLog/models/userGrant"
	"shareLog/services"
)

type authController struct {
	base.BaseController
	authService services.Auth
}

type Controller interface {
	base.LoadableController
	InviteUser(c *gin.Context)
}

func (a *authController) LoadController(engine *gin.Engine) {
	auth := engine.Group("/auth")

	{
		auth.POST("/invite", a.InviteUser)
	}
}

type ControllerProvider struct {
}

func (a ControllerProvider) Provide() any {
	authService := di.Get[services.Auth]()
	baseController := di.Get[base.BaseController]()
	instance := authController{
		baseController,
		authService,
	}

	return &instance
}

func (a *authController) InviteUser(c *gin.Context) {
	user := a.GetUser(c)
	if user == nil {
		c.Status(401)
	}

	var createInviteDto dto.CreateInvite
	err := c.BindJSON(&createInviteDto)
	if err != nil {
		c.Status(400)
		return
	}

	pk, _ := user.EncryptionKey.PrivateKey.Key()

	invite, _ := a.authService.CreateUserInvite(userGrant.GRANT_OWNER, pk)
	c.JSON(200, models.GetResponse(invite))
}
