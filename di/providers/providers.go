package providers

import (
	"gorm.io/gorm"
	"shareLog/controllers/log"
	"shareLog/data"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/di/lib"
	"shareLog/services"
)

func InitDi() {
	lib.RegisterProvider[*gorm.DB](di.Container, data.DatabaseProvider{})
	lib.RegisterProvider[services.Crypto](di.Container, services.CryptoProvider{})
	lib.RegisterProvider[services.Logger](di.Container, services.LoggerProvider{})
	lib.RegisterProvider[repository.LogRepository](di.Container, repository.LogRepositoryProvider{})
	lib.RegisterProvider[log.LogController](di.Container, log.LogControllerProvider{})
	lib.RegisterProvider[repository.KeyRepository](di.Container, repository.KeyRepositoryProvider{})
}
