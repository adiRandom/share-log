package services

import (
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/dto"
)

type logger struct {
	cryptoService Crypto
	repository    repository.LogRepository
}

type Logger interface {
	SaveLog(dto dto.Log) (*models.Log, error)
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
	println(l.cryptoService.DecryptOwnerLevel(doubleEncryptedLog))

	if err != nil {
		return nil, err
	}

	model := models.NewLog(doubleEncryptedLog)
	err = l.repository.Create(&model)
	if err != nil {
		return nil, err
	}

	return &model, nil
}
