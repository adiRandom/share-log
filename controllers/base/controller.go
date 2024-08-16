package base

import (
	"github.com/gin-gonic/gin"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/middleware"
	"shareLog/models"
	"shareLog/services"
)

type BaseController interface {
	GetUser(c *gin.Context) *models.User
	//WithAuth(g *gin.RouterGroup)
	//// GetUserSymmetricKey returns the symmetric key of the userGrant used to secure all their other encryption keys
	//GetUserSymmetricKey(c *gin.Context) string
}

type baseController struct {
	authService    services.Auth
	authMiddleware middleware.Auth
	userRepository repository.UserRepository
}

type BaseControllerProvider struct {
}

func (b BaseControllerProvider) Provide() any {
	authService := di.Get[services.Auth]()
	authMiddleware := di.Get[middleware.Auth]()
	userRepository := di.Get[repository.UserRepository]()
	return &baseController{authService: authService, authMiddleware: authMiddleware, userRepository: userRepository}
}

func (b *baseController) GetUser(c *gin.Context) *models.User {
	//jwt, exists := c.Get(constants.ContextJWTKey)
	//if !exists {
	//	c.Status(401)
	//	return nil
	//}
	//
	//user := b.authService.GetAuthUser(jwt.(jwtLib.Token))
	//return user

	return b.userRepository.GetById(1000)
}

func (b *baseController) GetUserSymmetricKey(c *gin.Context) string {
	panic("implement me")
}

func (b *baseController) WithAuth(g *gin.RouterGroup) {
	g.Use(b.authMiddleware.AuthUser)
}
