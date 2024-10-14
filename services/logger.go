package services

import (
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
	"shareLog/models"
	"shareLog/models/dto"
	"shareLog/models/encryption"
	"shareLog/models/userGrant"
)

type logger struct {
	cryptoService Crypto
	keyRepository repository.KeyRepository
	logRepository repository.LogRepository
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
		logRepository: logRepository,
	}
	return instance
}

func (l *logger) SaveLog(dto dto.Log) (*models.Log, error) {
	doubleEncryptedLog, err := l.cryptoService.EncryptOwnerLevel(dto.ClientEncryptedStackTrace)

	if err != nil {
		return nil, err
	}

	model := models.NewLog(doubleEncryptedLog)
	err = l.logRepository.Save(&model)
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
	err = l.logRepository.Save(&model)
	if err != nil {
		return
	}

	return
}

func (l *logger) HaveAccessToLog(id uint, user *models.User) (bool, error) {
	log := l.logRepository.GetById(id)

	if log == nil {
		return false, lib.Error{Msg: "No log with given id"}
	}

	if user.Grant == userGrant.Types.GrantOwner {
		return true, nil
	} else if user.Grant == userGrant.Types.GrantClient {
		key, err := l.keyRepository.GetAcquiredSharedKeyForLogId(user.ID, id)
		hasAccess := key != nil && err == nil
		return hasAccess, err
	}

	return false, nil
}

func (l *logger) GetDecryptedLog(id uint, user *models.User, userSymmetricKey string) (*models.DecryptedLog, error) {
	log := l.logRepository.GetById(id)

	if log == nil {
		return nil, lib.Error{Msg: "No log with given id"}
	}

	var keys lib.Pair[*encryption.Key, *encryption.Key]

	if user.Grant == userGrant.Types.GrantOwner {
		keys = l.getKeysForOwner(user)
	} else if user.Grant == userGrant.Types.GrantClient {
		keys = l.getKeysForClient(user, id)
	}

	ownerKey := keys.First
	clientKey := keys.Second

	stackTrace, err := l.cryptoService.DecryptMessage(&DecryptOptions{
		Data:            log.DoubleEncryptedStackTrace,
		Usr:             user,
		UsrSymmetricKey: userSymmetricKey,
		ClientLevelKey:  clientKey,
		OwnerLevelKey:   ownerKey,
	})

	if err != nil {
		return nil, err
	}
	return models.NewDecryptedLog(stackTrace), nil
}

// Returns [ownerKey, clientKey] for an owner grant user
func (l *logger) getKeysForOwner(user *models.User) lib.Pair[*encryption.Key, *encryption.Key] {
	ownerKey := lib.Find(user.EncryptionKeys, func(key encryption.Key) bool {
		return key.UserGrant == userGrant.Types.GrantOwner
	})

	clientKey := lib.Find(user.EncryptionKeys, func(key encryption.Key) bool {
		return key.UserGrant == userGrant.Types.GrantClient
	})

	return lib.Pair[*encryption.Key, *encryption.Key]{
		First:  ownerKey,
		Second: clientKey,
	}
}

// Returns [ownerKey, clientKey] for a client grant user. T
// he owner key will be a shared key acquired by the user
func (l *logger) getKeysForClient(user *models.User, logId uint) lib.Pair[*encryption.Key, *encryption.Key] {
	ownerKey := lib.Find(user.EncryptionKeys, func(key encryption.Key) bool {
		return key.UserGrant == userGrant.Types.GrantPartialOwner && *key.LogId == logId
	})

	clientKey := lib.Find(user.EncryptionKeys, func(key encryption.Key) bool {
		return key.UserGrant == userGrant.Types.GrantClient
	})

	return lib.Pair[*encryption.Key, *encryption.Key]{
		First:  ownerKey,
		Second: clientKey,
	}
}
