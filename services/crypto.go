package services

import (
	"errors"
	eciesgo "github.com/ecies/go/v2"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/encryption"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const saltSize = 32

type crypto struct {
	keyRepository repository.KeyRepository
}

func (c *crypto) GetEncryptionKeyForNewUser(inviteJWE string, encryptionKey string) (*encryption.EncryptionKey, error) {
	masterKey, err := c.getMasterKey(inviteJWE)
	if err != nil {
		return nil, err
	}

	// TODO: Encrypt the key and save it in the db
	return &masterKey, nil
}

func (c *crypto) getMasterKey(inviteJwe string) (encryption.EncryptionKey, error) {
	// TODO: Decrypt the inviteJwe and extract the master key

	// TODO: Mock code
	key := c.keyRepository.GetFirst(encryption.OWNER_PUBLIC_KEY)
	if key == nil {
		return encryption.EncryptionKey{}, errors.New("master key not found")
	}
	return *key, nil
}

func (c *crypto) PasswordDerivation(password string, salt string) (string, error) {
	saltedPassword := password + salt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), bcrypt.DefaultCost)
	return string(hashedPassword), err
}

func (c *crypto) GenerateSalt() string {
	saltBytes := make([]byte, saltSize)

	for i := range saltBytes {
		saltBytes[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(saltBytes)
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
	GetEncryptionKeyForNewUser(inviteJWE string, encryptionKey string) (*encryption.EncryptionKey, error)
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
