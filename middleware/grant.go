package middleware

import (
	"github.com/gin-gonic/gin"
	"shareLog/di"
	controllerLib "shareLog/lib/controller"
	"shareLog/models/userGrant"
	"shareLog/services"
)

type grant struct {
	authService services.Auth
}

type Grant interface {
	CheckUserGrant(c *gin.Context, grant userGrant.Type)
}

type GrantProvider struct {
}

func (p GrantProvider) Provide() any {
	authService := di.Get[services.Auth]()

	grantMiddleware := grant{
		authService: authService,
	}

	return &grantMiddleware
}

func (g *grant) CheckUserGrant(c *gin.Context, grant userGrant.Type) {
	user := controllerLib.GetUser(c, g.authService)
	if user == nil {
		c.Status(401)
		c.Abort()
		return
	}

	if user.Grant.AuthorityLevel < grant.AuthorityLevel {
		c.Status(403)
		c.Abort()
		return
	}

	c.Next()
}
