package services

import (
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
	"shareLog/models"
	"shareLog/models/dto"
	"shareLog/models/userGrant"
)

type logger struct {
	cryptoService Crypto
	repository    repository.LogRepository
}

type Logger interface {
	SaveLog(dto dto.Log) (*models.Log, error)
	// TODO: Delete
	SavePlainLog(dto dto.Log)
	HaveAccessToLog(id uint, user *models.User) (bool, error)
	GetDecryptedLog(id uint, user *models.User, userSymmetricKey string) (*models.DecryptedLog, error)
}

type LoggerProvider struct {
}

func (l LoggerProvider) Provide() any {
	cryptoService := di.Get[Crypto]()
	logRepository := di.Get[repository.LogRepository]()
	var instance Logger = &logger{
		cryptoService: cryptoService,
		repository:    logRepository,
	}
	return instance
}

func (l *logger) SaveLog(dto dto.Log) (*models.Log, error) {
	doubleEncryptedLog, err := l.cryptoService.EncryptOwnerLevel(dto.ClientEncryptedStackTrace)

	if err != nil {
		return nil, err
	}

	model := models.NewLog(doubleEncryptedLog)
	err = l.repository.Save(&model)
	if err != nil {
		return nil, err
	}

	return &model, nil
}

// TODO: Delete
func (l *logger) SavePlainLog(dto dto.Log) {
	encryptedLog, err := l.cryptoService.EncryptClientLevel(dto.ClientEncryptedStackTrace)
	if err != nil {
		return
	}
	doubleEncryptedLog, err := l.cryptoService.EncryptOwnerLevel(encryptedLog)

	if err != nil {
		return
	}

	model := models.NewLog(doubleEncryptedLog)
	err = l.repository.Save(&model)
	if err != nil {
		return
	}

	return
}

func (l *logger) HaveAccessToLog(id uint, user *models.User) (bool, error) {
	log := l.repository.GetById(id)

	if log == nil {
		return false, lib.Error{Msg: "No log with given id"}
	}

	return user.Grant == userGrant.Types.GrantOwner, nil

	// TODO: Implement for client
}

func (l *logger) GetDecryptedLog(id uint, user *models.User, userSymmetricKey string) (*models.DecryptedLog, error) {
	log := l.repository.GetById(id)

	if log == nil {
		return nil, lib.Error{Msg: "No log with given id"}
	}

	stackTrace, err := l.cryptoService.DecryptMessage(&DecryptOptions{
		Data:            log.DoubleEncryptedStackTrace,
		Usr:             user,
		UsrSymmetricKey: userSymmetricKey,
	})

	if err != nil {
		return nil, err
	}
	return models.NewDecryptedLog(stackTrace), nil
}
