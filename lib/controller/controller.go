package controller

import (
	"github.com/gin-gonic/gin"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"shareLog/constants"
	"shareLog/models"
	"shareLog/services"
)

func GetUser(c *gin.Context, authService services.Auth) *models.User {
	jwt, exists := c.Get(constants.ContextJWTKey)
	if !exists {
		c.Status(401)
		return nil
	}

	user := authService.GetAuthUser(*jwt.(*jwtLib.Token))
	return user
}
