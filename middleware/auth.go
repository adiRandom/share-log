package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"shareLog/constants"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/services"
	"strings"
)

type auth struct {
	userRepository repository.UserRepository
	cryptoService  services.Crypto
	authService    services.Auth
}

type Auth interface {
	DoAuth(c *gin.Context)
}

type AuthProvider struct {
}

func (p AuthProvider) Provide() any {
	userRepository := di.Get[repository.UserRepository]()

	cryptoService := di.Get[services.Crypto]()
	authService := di.Get[services.Auth]()

	authMiddleware := auth{
		userRepository: userRepository,
		cryptoService:  cryptoService,
		authService:    authService,
	}

	return &authMiddleware
}

func (a *auth) DoAuth(c *gin.Context) {
	userAuthHeaderValue := c.GetHeader(constants.UserAuthHeader)
	apiKeyAuthHeaderValue := c.GetHeader(constants.ApiKeyHeader)

	var parsedJwt *jwt.Token
	if userAuthHeaderValue != "" {
		parsedJwt = a.authUser(userAuthHeaderValue, c)
	} else if apiKeyAuthHeaderValue != "" {
		parsedJwt = a.authApp(apiKeyAuthHeaderValue, c)
	} else {
		c.Status(401)
		c.Abort()
		return
	}

	if parsedJwt == nil {
		c.Status(401)
		c.Abort()
		return
	}

	c.Set(constants.ContextJWTKey, parsedJwt)
	c.Next()
}

func (a *auth) authUser(authHeaderVal string, c *gin.Context) *jwt.Token {
	jwe, _ := strings.CutPrefix(authHeaderVal, constants.TokenHeaderPrefix)

	serializedJwt, err := a.cryptoService.DecodeJwe(jwe)
	if err != nil {
		c.Status(401)
		c.Abort()
		return nil
	}

	parsedJwt, validationError := a.authService.ParseAndValidateJWT(serializedJwt)
	if validationError != nil {
		c.Status(401)
		println(validationError)
		c.Abort()
		return nil
	}

	return parsedJwt
}

func (a *auth) authApp(apiKey string, c *gin.Context) *jwt.Token {
	appJwt, err := a.authService.GenerateAppAuthToken(apiKey)

	if err != nil {
		c.Status(401)
		c.Abort()
		return nil
	}

	return appJwt
}
