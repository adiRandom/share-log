package providers

import (
	"gorm.io/gorm"
	"shareLog/controllers/auth"
	"shareLog/controllers/base"
	"shareLog/controllers/config"
	"shareLog/controllers/log"
	"shareLog/controllers/logPermissionRequest"
	"shareLog/data"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/di/diLib"
	"shareLog/middleware"
	"shareLog/services"
)

func InitDi() {
	diLib.RegisterProvider[repository.KeyRepository](di.Container, repository.KeyRepositoryProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[*gorm.DB](di.Container, data.DatabaseProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[services.Crypto](di.Container, services.CryptoProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[services.Logger](di.Container, services.LoggerProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[repository.LogRepository](di.Container, repository.LogRepositoryProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[repository.UserRepository](di.Container, repository.UserRepositoryProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[services.Auth](di.Container, services.AuthProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[middleware.Auth](di.Container, middleware.AuthProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[middleware.Grant](di.Container, middleware.GrantProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[base.BaseController](di.Container, base.BaseControllerProvider{}, diLib.FactoryProvider)
	diLib.RegisterProvider[repository.InviteRepository](di.Container, repository.InviteRepositoryProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[auth.Controller](di.Container, auth.ControllerProvider{}, diLib.SingletonProvider, diLib.Binding[base.LoadableController]{})
	diLib.RegisterProvider[log.LogController](di.Container, log.LogControllerProvider{}, diLib.SingletonProvider, diLib.Binding[base.LoadableController]{})
	diLib.RegisterProvider[logPermissionRequest.Controller](di.Container, logPermissionRequest.ControllerProvider{}, diLib.SingletonProvider, diLib.Binding[base.LoadableController]{})
	diLib.RegisterProvider[repository.LogPermissionRepository](di.Container, repository.LogPermissionRepositoryProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[services.PermissionRequest](di.Container, services.PermissionRequestProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[services.Mailer](di.Container, services.MailerProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[services.KeyManager](di.Container, services.KeyManagerProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[repository.ApiKeyRepository](di.Container, repository.ApiKeyRepositoryProvider{}, diLib.SingletonProvider)
	diLib.RegisterProvider[config.Controller](di.Container, config.ControllerProvider{}, diLib.SingletonProvider, diLib.Binding[base.LoadableController]{})
}
