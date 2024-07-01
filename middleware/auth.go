package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"shareLog/constants"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/services"
)

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

func (p AuthProvider) Provide() Auth {
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
	jwe := getJWEFromHeader(c)
	if jwe == nil {
		return
	}

	// TODO: Get JWT from JWE and validate
	jwt := a.cryptoService.DecodeJWE(jwe)
	validationError := a.authService.ValidateJWT(*jwt)
	if validationError != nil {
		c.Status(403)
		println(validationError)
		return
	}

	c.Set(constants.ContextJWTKey, jwt)
	c.Next()
}

func getJWEFromHeader(c *gin.Context) *jose.JSONWebEncryption {
	jweString := c.GetHeader("Authorization")
	if jweString == "" {
		c.Status(401)
		println("No JWE provided")
		return nil
	}

	jwe, err := jose.ParseEncryptedJSON(jweString,
		[]jose.KeyAlgorithm{constants.AuthJWEKeyAlgo},
		[]jose.ContentEncryption{constants.AuthJWEContentAlgo},
	)

	if err != nil {
		c.Status(401)
		println(err)
		return nil
	}

	return jwe
}
