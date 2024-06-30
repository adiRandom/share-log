package main

import (
	"github.com/gin-gonic/gin"
	"shareLog/controllers"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/di/providers"
	"shareLog/models/encryption"
)

func createMasterKeyForOwner() {
	keyRepository := di.Get[repository.KeyRepository]()
	key := keyRepository.GetPublicKeyForDataOwner()
	if key == nil {
		keyRepository.Create(encryption.OWNER_PUBLIC_KEY)
	}
}

func main() {
	providers.InitDi()

	engine := gin.Default()
	controllers.LoadAllController(engine)

	// TODO: remove test code
	createMasterKeyForOwner()

	engine.Run()
}
