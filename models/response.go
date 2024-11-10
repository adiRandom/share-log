package models

import (
	"github.com/gin-gonic/gin"
	"shareLog/models/dto"
)

func GetResponse(data any, error *dto.Error) any {
	return gin.H{
		"data":  data,
		"error": error,
	}
}
