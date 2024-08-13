package base

import (
	"github.com/gin-gonic/gin"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"shareLog/constants"
	"shareLog/di"
	"shareLog/middleware"
	"shareLog/models"
	"shareLog/services"
)

type BaseController interface {
	GetUser(c *gin.Context) *models.User
	WithAuth(g *gin.RouterGroup)
	// GetUserSymmetricKey returns the symmetric key of the user used to secure all their other encryption keys
	GetUserSymmetricKey(c *gin.Context) string
}

type baseController struct {
	authService    services.Auth
	authMiddleware middleware.Auth
}

type BaseControllerProvider struct {
}

func (b BaseControllerProvider) Provide() BaseController {
	authService := di.Get[services.Auth]()
	authMiddleware := di.Get[middleware.Auth]()
	return &baseController{authService: authService, authMiddleware: authMiddleware}
}

func (b *baseController) GetUser(c *gin.Context) *models.User {
	jwt, exists := c.Get(constants.ContextJWTKey)
	if !exists {
		c.Status(401)
		return nil
	}

	user := b.authService.GetAuthUser(jwt.(jwtLib.Token))
	return user
}

func (b *baseController) GetUserSymmetricKey(c *gin.Context) string {
	jwt, exists := c.Get(constants.ContextJWTKey)
	if !exists {
		c.Status(401)
		return ""
	}

	return b.authService.GetUserSymmetricKey(jwt.(jwtLib.Token))
}

func (b *baseController) WithAuth(g *gin.RouterGroup) {
	g.Use(b.authMiddleware.AuthUser)
}
