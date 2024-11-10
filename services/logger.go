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
	keyManager    KeyManager
	keyRepository repository.KeyRepository
	logRepository repository.LogRepository
}

type Logger interface {
	SaveLog(dto dto.Log) (*models.Log, error)
	// TODO: Delete
	SavePlainLog(dto dto.Log)
	HaveAccessToLog(id uint, user *models.User) (bool, error)
	GetDecryptedLog(id uint, user *models.User, userSymmetricKey string) (*models.DecryptedLog, error)
	CreateWithClientAccess(logId uint, user *models.User, userSymmetricKey string, sharedKey *encryption.Key) error
}

type LoggerProvider struct {
}

func (l LoggerProvider) Provide() any {
	cryptoService := di.Get[Crypto]()
	logRepository := di.Get[repository.LogRepository]()
	var instance Logger = &logger{
		cryptoService: cryptoService,
		logRepository: logRepository,
		keyRepository: di.Get[repository.KeyRepository](),
		keyManager:    di.Get[KeyManager](),
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
	log := l.getLogForUser(id, user.Grant)

	if log == nil {
		return nil, lib.Error{Msg: "No log with given id"}
	}

	keys := l.keyManager.GetDecryptionKeysForLog(user, id)

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

func (l *logger) getLogForUser(logId uint, grant userGrant.Type) *models.Log {
	if grant == userGrant.Types.GrantOwner {
		return l.logRepository.GetById(logId)
	} else if grant == userGrant.Types.GrantClient {
		return l.logRepository.GetByRefId(logId)
	}

	return nil
}

func (l *logger) CreateWithClientAccess(logId uint, user *models.User, userSymmetricKey string, sharedKey *encryption.Key) error {
	decryptedLog, err := l.GetDecryptedLog(logId, user, userSymmetricKey)
	if err != nil {
		return err
	}

	encryptedLog, err := l.cryptoService.EncryptClientLevel(decryptedLog.StackTrace)
	if err != nil {
		return err
	}
	doubleEncryptedLog, err := l.cryptoService.EncryptMessage(encryptedLog, sharedKey)

	if err != nil {
		return err
	}

	model := models.NewLog(doubleEncryptedLog)
	model.RefLogId = &logId
	err = l.logRepository.Save(&model)
	if err != nil {
		return err
	}

	return nil
}
