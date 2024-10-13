package services

import (
	"shareLog/config"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
	"shareLog/models"
	"shareLog/models/userGrant"
	"slices"
)

type permissionRequest struct {
	logPermissionRepository repository.LogPermissionRepository
	cryptoService           Crypto
	keyRepository           repository.KeyRepository
}

type PermissionRequest interface {
	RequestPermission(logId uint) error
	ApprovePermission(request models.PermissionRequest) error
	DenyPermission(request models.PermissionRequest) error
	ResetPermissionRequest(request models.PermissionRequest) error
	GetPermissionRequests(user *models.User) ([]lib.Pair[models.PermissionRequest, bool], error)
}

type PermissionRequestProvider struct {
}

func (l PermissionRequestProvider) Provide() any {
	logPermissionRepository := di.Get[repository.LogPermissionRepository]()
	cryptoService := di.Get[Crypto]()
	keyRepository := di.Get[repository.KeyRepository]()
	var instance PermissionRequest = &permissionRequest{
		logPermissionRepository: logPermissionRepository,
		cryptoService:           cryptoService,
		keyRepository:           keyRepository,
	}
	return instance
}

func (p *permissionRequest) RequestPermission(logId uint) error {
	request := models.PermissionRequest{
		LogID:  logId,
		Status: models.PermissionRequestStatuses.Pending,
	}

	return p.logPermissionRepository.Save(&request)
}

func (p *permissionRequest) ApprovePermission(request models.PermissionRequest) error {
	salt := p.cryptoService.GenerateSalt()
	key, err := p.cryptoService.CreateNewEncryptionKey(userGrant.Types.GrantShared, config.GetSecrets().LogSharingSecret, salt)
	if err != nil {
		return err
	}

	key.LogId = &request.LogID
	key.Salt = salt
	err = p.keyRepository.Save(key)
	if err != nil {
		return err
	}

	updatedRequest := models.PermissionRequest{
		Model:  request.Model,
		LogID:  request.LogID,
		Status: models.PermissionRequestStatuses.Approved,
	}

	return p.logPermissionRepository.Save(&updatedRequest)
}

func (p *permissionRequest) DenyPermission(request models.PermissionRequest) error {
	updatedRequest := models.PermissionRequest{
		Model:  request.Model,
		LogID:  request.LogID,
		Status: models.PermissionRequestStatuses.Denied,
	}

	return p.logPermissionRepository.Save(&updatedRequest)
}

func (p *permissionRequest) ResetPermissionRequest(request models.PermissionRequest) error {
	updatedRequest := models.PermissionRequest{
		Model:  request.Model,
		LogID:  request.LogID,
		Status: models.PermissionRequestStatuses.Pending,
	}

	return p.logPermissionRepository.Save(&updatedRequest)
}

func (p *permissionRequest) GetPermissionRequests(user *models.User) ([]lib.Pair[models.PermissionRequest, bool], error) {
	acquiredRequests, err := p.logPermissionRepository.GetAllAcquiredByUser(user.ID)
	if err != nil {
		return nil, err
	}

	unacquiredRequests, err := p.logPermissionRepository.GetAllUnacquiredByUser(user.ID)
	if err != nil {
		return nil, err
	}

	acquiredRequestsWithStatus := lib.Map(acquiredRequests,
		func(request models.PermissionRequest) lib.Pair[models.PermissionRequest, bool] {
			return lib.Pair[models.PermissionRequest, bool]{
				First:  request,
				Second: true,
			}
		})

	unacquiredRequestsWithStatus := lib.Map(unacquiredRequests,
		func(request models.PermissionRequest) lib.Pair[models.PermissionRequest, bool] {
			return lib.Pair[models.PermissionRequest, bool]{
				First:  request,
				Second: false,
			}
		})

	return slices.Concat(acquiredRequestsWithStatus, unacquiredRequestsWithStatus), nil
}
