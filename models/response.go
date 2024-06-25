package models

import "github.com/gin-gonic/gin"

func GetResponse(data any) any {
	return gin.H{
		"data": data,
	}
}
