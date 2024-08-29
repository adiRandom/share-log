package middleware

import (
	"github.com/gin-gonic/gin"
	"shareLog/constants"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/services"
	"strings"
)

const tokenPrefix = "Bearer "

type auth struct {
	userRepository repository.UserRepository
	cryptoService  services.Crypto
	authService    services.Auth
}

type Auth interface {
	AuthUser(c *gin.Context)
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

func (a *auth) AuthUser(c *gin.Context) {

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.Status(401)
		return
	}

	jwe, _ := strings.CutPrefix(authHeader, tokenPrefix)

	serializedJwt, err := a.cryptoService.DecodeJwe(jwe)
	if err != nil {
		c.Status(401)
		return
	}

	jwt, validationError := a.authService.ParseAndValidateJWT(serializedJwt)
	if validationError != nil {
		c.Status(401)
		println(validationError)
		return
	}

	c.Set(constants.ContextJWTKey, jwt)
	c.Next()
}
