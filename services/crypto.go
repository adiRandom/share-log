package services

import (
	eciesgo "github.com/ecies/go/v2"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/encryption"
)

type crypto struct {
	keyRepository repository.KeyRepository
}

func (c *crypto) GetEncryptionKeyForNewUser(inviteJWE string, encryptionKey string) (encryption.EncryptionKey, error) {
	//TODO implement me
	panic("implement me")
}

func (c *crypto) PasswordDerivation(password string, salt string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (c *crypto) GenerateSalt() string {
	//TODO implement me
	panic("implement me")
}

type Crypto interface {
	EncryptOwnerLevel(data string) (string, error)
	DecryptOwnerLevel(data string, usr *models.User) (string, error)
	PasswordDerivation(password string, salt string) (string, error)
	GenerateSalt() string
	/*
		Extract from the JWE the encryption key of the user that crated the invite

		@param inviteJWE: The JWE that contains the user id of the user that created the invite, the access level
		and the key to decrypt the master key for that access level

		@param encryptionKey: The key used to encrypt the master private key for the new user
		@return The encryption key of the user that created the invite
	*/
	GetEncryptionKeyForNewUser(inviteJWE string, encryptionKey string) (encryption.EncryptionKey, error)
}

type CryptoProvider struct {
}

func (c CryptoProvider) Provide() Crypto {
	keyRepository := di.Get[repository.KeyRepository]()
	var instance Crypto = &crypto{keyRepository}
	return instance
}

func (c *crypto) EncryptOwnerLevel(data string) (string, error) {
	publicKey := c.keyRepository.GetPublicKeyForDataOwner().PublicKey
	encryptedBytes, err := eciesgo.Encrypt(publicKey.Key, []byte(data))
	return string(encryptedBytes), err
}

func (c *crypto) DecryptOwnerLevel(data string, usr *models.User) (string, error) {
	privateKey, err := usr.EncryptionKey.PrivateKey.Key()
	if err != nil {
		return "", err
	}

	decryptedBytes, err := eciesgo.Decrypt(privateKey, []byte(data))
	return string(decryptedBytes), err
}
