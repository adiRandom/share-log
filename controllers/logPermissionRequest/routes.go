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
	keyManager               services.KeyManager
	keyRepository            repository.KeyRepository
}

type Controller interface {
	base.LoadableController
	LoadController(engine *gin.Engine)
}

type ControllerProvider struct {
}

func (p ControllerProvider) Provide() any {
	var instance Controller = &controller{
		BaseController:           di.Get[base.BaseController](),
		permissionRequestService: di.Get[services.PermissionRequest](),
		logPermissionRepository:  di.Get[repository.LogPermissionRepository](),
		keyManager:               di.Get[services.KeyManager](),
		keyRepository:            di.Get[repository.KeyRepository](),
	}
	return instance
}

func (l *controller) LoadController(engine *gin.Engine) {
	rootGroup := engine.Group("/log")
	l.WithAuth(rootGroup)
	{
		rootGroup.GET("/list", l.getPermissionRequests)
	}

	clientGroup := rootGroup.Group("/:id/permission")
	{
		clientGroup.POST("/", l.requestPermission)
		clientGroup.POST("/acquire", l.acquireSharedKey)
		clientGroup.PATCH("/reset", l.resetPermissionRequest)
	}

	ownerGroup := rootGroup.Group("/:id/permission/owner")
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
		c.JSON(500, models.GetResponse(nil, &dto.Error{
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

	user := l.GetUser(c)
	userSymmetricKey := l.GetUserSymmetricKey(c)

	err = l.permissionRequestService.ApprovePermission(user, userSymmetricKey, *request)
	if err != nil {
		c.JSON(500, models.GetResponse(nil, &dto.Error{
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
		c.JSON(500, models.GetResponse(nil, &dto.Error{
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
		c.JSON(500, models.GetResponse(nil, &dto.Error{
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

	c.JSON(200, models.GetResponse(responseModel, nil))
}

func (l *controller) acquireSharedKey(c *gin.Context) {
	user := l.GetUser(c)
	logId, err := l.GetUIntParam(c, "id")
	if err != nil {
		return
	}

	sharedKey, err := l.keyRepository.GetUnacquiredSharedKey(user.ID, logId)
	if err != nil {
		c.Status(404)
		return
	}

	userSymmetricKey := l.GetUserSymmetricKey(c)
	_, err = l.keyManager.AcquireSharedKey(user, sharedKey, userSymmetricKey, true)

	if err != nil {
		c.JSON(500, models.GetResponse(nil, &dto.Error{Code: 500, Message: err.Error()}))
		return
	}

	c.Status(201)
}
