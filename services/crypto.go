package services

import (
	eciesgo "github.com/ecies/go/v2"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/models"
)

type crypto struct {
	keyRepository repository.KeyRepository
}

type Crypto interface {
	EncryptOwnerLevel(data string) (string, error)
	DecryptOwnerLevel(data string) (string, error)
}

type CryptoProvider struct {
}

func (c CryptoProvider) Provide() Crypto {
	keyRepository := di.Get[repository.KeyRepository]()
	var instance Crypto = &crypto{keyRepository}
	return instance
}

func (c *crypto) EncryptOwnerLevel(data string) (string, error) {
	publicKey := c.getPublicKey()
	encryptedBytes, err := eciesgo.Encrypt(publicKey, []byte(data))
	return string(encryptedBytes), err
}

func (c *crypto) DecryptOwnerLevel(data string) (string, error) {
	privateKey := c.getPrivateKey()
	decryptedBytes, err := eciesgo.Decrypt(privateKey, []byte(data))
	return string(decryptedBytes), err
}

func (c *crypto) getPublicKey() *eciesgo.PublicKey {
	key := c.generateKey()
	return key.PublicKey
}

func (c *crypto) getPrivateKey() *eciesgo.PrivateKey {
	key, _ := c.keyRepository.GetFirstKey()
	// For testing purposes
	// Normally the key should be encrypted
	privateKey, _ := eciesgo.NewPrivateKeyFromHex(key.EncryptedPrivateKeyHex)
	return privateKey
}

func (c *crypto) generateKey() *eciesgo.PrivateKey {
	key, err := eciesgo.GenerateKey()
	if err != nil {
		println(err)
		return nil
	}

	keyModel := models.NewEncryptionKey(*key)

	err = c.keyRepository.Create(&keyModel)
	if err != nil {
		println(err)
		return nil
	}

	return key
}
