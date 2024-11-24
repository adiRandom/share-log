package base

import (
	"github.com/gin-gonic/gin"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"shareLog/constants"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
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
	IsApiKeyAuth(c *gin.Context) bool
	GetApiKey(c *gin.Context) (*models.ApiKey, error)
}

type baseController struct {
	authService      services.Auth
	authMiddleware   middleware.Auth
	grantMiddleware  middleware.Grant
	userRepository   repository.UserRepository
	keyManager       services.KeyManager
	apiKeyRepository repository.ApiKeyRepository
}

type BaseControllerProvider struct {
}

func (b BaseControllerProvider) Provide() any {
	return &baseController{
		authService:      di.Get[services.Auth](),
		authMiddleware:   di.Get[middleware.Auth](),
		userRepository:   di.Get[repository.UserRepository](),
		grantMiddleware:  di.Get[middleware.Grant](),
		keyManager:       di.Get[services.KeyManager](),
		apiKeyRepository: di.Get[repository.ApiKeyRepository](),
	}
}

func getJwtFromContext(c *gin.Context) *jwtLib.Token {
	jwt, exists := c.Get(constants.ContextJWTKey)
	if !exists {
		c.Status(401)
		return nil
	}

	return jwt.(*jwtLib.Token)
}

// Get the current JWT to see if the current user is user or app
func (b *baseController) IsApiKeyAuth(c *gin.Context) bool {
	parsedJwt := getJwtFromContext(c)
	if parsedJwt == nil {
		return false
	}

	return b.authService.GetAuthGrant(*parsedJwt) == userGrant.Types.GrantApp
}

func (b *baseController) GetUser(c *gin.Context) *models.User {
	if b.IsApiKeyAuth(c) {
		c.Status(403)
		return nil
	}
	return controllerLib.GetUser(c, b.authService)
}

func (b *baseController) GetUserSymmetricKey(c *gin.Context) string {
	if b.IsApiKeyAuth(c) {
		c.Status(403)
		return ""
	}

	parsedJwt := getJwtFromContext(c)
	if parsedJwt == nil {
		return ""
	}
	key, err := b.keyManager.GetUserSymmetricKey(*parsedJwt)
	if err != nil {
		c.Status(401)
		return ""
	}

	return key
}

func (b *baseController) WithAuth(g *gin.RouterGroup) {
	g.Use(b.authMiddleware.DoAuth)
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
		c.JSON(400, models.GetResponse(nil, &dto.Error{
			Code:    400,
			Message: "Malformed URL",
		}))
		return 0, err
	}

	paramUint := uint(paramInt64)
	return paramUint, nil
}

func (b *baseController) GetApiKey(c *gin.Context) (*models.ApiKey, error) {
	apiKey := c.GetHeader(constants.ApiKeyHeader)
	if apiKey == "" {
		return nil, lib.Error{Msg: "No api key provided"}
	}
	apiKeyModel := b.apiKeyRepository.GetByKey(apiKey)
	if apiKeyModel == nil {
		return nil, lib.Error{Msg: "API key not found"}
	}

	return apiKeyModel, nil
}
