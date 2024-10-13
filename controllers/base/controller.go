package base

import (
	"github.com/gin-gonic/gin"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"shareLog/constants"
	"shareLog/data/repository"
	"shareLog/di"
	controllerLib "shareLog/lib/controller"
	"shareLog/middleware"
	"shareLog/models"
	"shareLog/models/dto"
	"shareLog/models/userGrant"
	"shareLog/services"
	"strconv"
)

type BaseController interface {
	GetUser(c *gin.Context) *models.User
	//  WithAuth(g *gin.RouterGroup)

	// GetUserSymmetricKey Return the key this user uses to encrypt and decrypt all their other keys
	GetUserSymmetricKey(c *gin.Context) string
	WithAuth(g *gin.RouterGroup)
	WithMinGrant(g *gin.RouterGroup, grant userGrant.Type)
	// GetUIntParam Try to get a param as uint. If the paring fails, an error is returned
	// and a 400 status is sent back as response
	GetUIntParam(c *gin.Context, paramName string) (uint, error)
}

type baseController struct {
	authService     services.Auth
	authMiddleware  middleware.Auth
	grantMiddleware middleware.Grant
	userRepository  repository.UserRepository
}

type BaseControllerProvider struct {
}

func (b BaseControllerProvider) Provide() any {
	authService := di.Get[services.Auth]()
	authMiddleware := di.Get[middleware.Auth]()
	grantMiddleware := di.Get[middleware.Grant]()
	userRepository := di.Get[repository.UserRepository]()

	return &baseController{
		authService:     authService,
		authMiddleware:  authMiddleware,
		userRepository:  userRepository,
		grantMiddleware: grantMiddleware,
	}
}

func (b *baseController) GetUser(c *gin.Context) *models.User {
	return controllerLib.GetUser(c, b.authService)
}

func (b *baseController) GetUserSymmetricKey(c *gin.Context) string {
	jwt, exists := c.Get(constants.ContextJWTKey)
	if !exists {
		c.Status(401)
		return ""
	}

	key, err := b.authService.GetUserSymmetricKey(*jwt.(*jwtLib.Token))
	if err != nil {
		c.Status(401)
		return ""
	}

	return key
}

func (b *baseController) WithAuth(g *gin.RouterGroup) {
	g.Use(b.authMiddleware.AuthUser)
}

func (b *baseController) WithMinGrant(g *gin.RouterGroup, grant userGrant.Type) {
	g.Use(func(c *gin.Context) {
		b.grantMiddleware.CheckUserGrant(c, grant)
	})
}

func (b *baseController) GetUIntParam(c *gin.Context, paramName string) (uint, error) {
	paramString := c.Param(paramName)
	paramInt64, err := strconv.ParseInt(paramString, 10, 64)
	if err != nil {
		c.JSON(400, models.GetResponse(dto.Error{
			Code:    400,
			Message: "Malformed URL",
		}))
		return 0, err
	}

	paramUint := uint(paramInt64)
	return paramUint, nil
}
