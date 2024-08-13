package services

import (
	"shareLog/data/repository"
	"shareLog/di"
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
	GetLog(id uint, user *models.User, userSymmetricKey string) (*models.DecryptedLog, error)
}

type LoggerProvider struct {
}

func (l LoggerProvider) Provide() Logger {
	cryptoService := di.Get[Crypto]()
	logRepository := di.Get[repository.LogRepository]()
	var instance Logger = &logger{
		cryptoService: cryptoService,
		repository:    logRepository,
	}
	return instance
}

func (l *logger) SaveLog(dto dto.Log) (*models.Log, error) {
	doubleEncryptedLog, err := l.cryptoService.EncryptOwnerLevel(dto.EncryptedStackTrace)

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

func (l *logger) GetLog(id uint, user *models.User, userSymmetricKey string) (*models.DecryptedLog, error) {
	encryptedLog := l.repository.GetById(id)

	ownerLevelDecryptedStackTrace, err := l.cryptoService.DecryptMessage(&DecryptOptions{
		Data:            encryptedLog.DoubleEncryptedStackTrace,
		Level:           userGrant.GRANT_OWNER,
		Usr:             user,
		UsrSymmetricKey: userSymmetricKey,
	})
	if err != nil {
		return nil, err
	}

	// TODO: Decrypt client level
	decryptedStackTrace, err := ownerLevelDecryptedStackTrace, nil
	if err != nil {
		return nil, err
	}

	decryptedLog := models.NewDecryptedLog(decryptedStackTrace)
	return &decryptedLog, nil
}
