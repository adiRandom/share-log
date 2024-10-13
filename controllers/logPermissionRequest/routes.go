package logPermissionRequest

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers/base"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
	"shareLog/models"
	"shareLog/models/dto"
	"shareLog/models/userGrant"
	"shareLog/services"
)

type controller struct {
	base.BaseController
	permissionRequestService services.PermissionRequest
	logPermissionRepository  repository.LogPermissionRepository
}

type Controller interface {
	base.LoadableController
	LoadController(engine *gin.Engine)
}

type ControllerProvider struct {
}

func (p ControllerProvider) Provide() any {
	baseController := di.Get[base.BaseController]()
	permissionRequestService := di.Get[services.PermissionRequest]()
	logPermissionRepository := di.Get[repository.LogPermissionRepository]()
	var instance Controller = &controller{
		baseController,
		permissionRequestService,
		logPermissionRepository,
	}
	return instance
}

func (l *controller) LoadController(engine *gin.Engine) {
	clientGroup := engine.Group("/log/:id/permission")
	ownerGroup := engine.Group("/log/:id/permission/owner")

	l.WithAuth(clientGroup)
	{
		clientGroup.GET("/", l.getPermissionRequests)
		clientGroup.POST("/", l.requestPermission)
		clientGroup.PATCH("/reset", l.resetPermissionRequest)
	}

	l.WithAuth(ownerGroup)
	l.WithMinGrant(ownerGroup, userGrant.Types.GrantOwner)
	{
		ownerGroup.PATCH("/", l.acceptPermissionRequest)
		ownerGroup.DELETE("/", l.denyPermissionRequest)
	}
}

func (l *controller) requestPermission(c *gin.Context) {
	logId, err := l.GetUIntParam(c, "id")
	if err != nil {
		return
	}

	err = l.permissionRequestService.RequestPermission(logId)
	if err != nil {
		c.JSON(500, models.GetResponse(dto.Error{
			Code:    500,
			Message: err.Error(),
		}))
		return
	}

	c.Status(201)
}

func (l *controller) acceptPermissionRequest(c *gin.Context) {
	logId, err := l.GetUIntParam(c, "id")
	if err != nil {
		return
	}

	request, err := l.logPermissionRepository.GetByLogId(logId)
	if err != nil {
		c.Status(404)
		return
	}

	err = l.permissionRequestService.ApprovePermission(*request)
	if err != nil {
		c.JSON(500, models.GetResponse(dto.Error{
			Code:    500,
			Message: err.Error(),
		}))
		return
	}

	c.Status(200)
}

func (l *controller) denyPermissionRequest(c *gin.Context) {
	logId, err := l.GetUIntParam(c, "id")
	if err != nil {
		return
	}

	request, err := l.logPermissionRepository.GetByLogId(logId)
	if err != nil {
		c.Status(404)
		return
	}

	err = l.permissionRequestService.DenyPermission(*request)
	if err != nil {
		c.JSON(500, models.GetResponse(dto.Error{
			Code:    500,
			Message: err.Error(),
		}))
		return
	}

	c.Status(200)
}

func (l *controller) resetPermissionRequest(c *gin.Context) {
	logId, err := l.GetUIntParam(c, "id")
	if err != nil {
		return
	}

	request, err := l.logPermissionRepository.GetByLogId(logId)
	if err != nil {
		c.Status(404)
		return
	}

	err = l.permissionRequestService.ResetPermissionRequest(*request)
	if err != nil {
		c.JSON(500, models.GetResponse(dto.Error{
			Code:    500,
			Message: err.Error(),
		}))
		return
	}

	c.Status(200)
}

func (l *controller) getPermissionRequests(c *gin.Context) {
	user := l.GetUser(c)

	requests, err := l.permissionRequestService.GetPermissionRequests(user)
	if err != nil {
		c.Status(500)
		return
	}

	responseModel := lib.Map(requests, func(request lib.Pair[models.PermissionRequest, bool]) dto.LogPermissionRequest {
		return dto.LogPermissionRequest{
			Id:       request.First.ID,
			LogId:    request.First.LogID,
			Status:   request.First.Status.Status,
			Acquired: request.Second,
		}
	})

	c.JSON(200, models.GetResponse(responseModel))
}
