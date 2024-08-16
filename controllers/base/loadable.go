package base

import "github.com/gin-gonic/gin"

type LoadableController interface {
	LoadController(c *gin.Engine)
}
