package services

import (
	eciesgo "github.com/ecies/go/v2"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"shareLog/constants"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
	"shareLog/models"
	"shareLog/models/encryption/keyType"
)

type crypto struct {
	keyRepository repository.KeyRepository
}

/*
	Options used to decrypt a message

	Data - The message to decrypt
	Usr - The user that has a key that can be used to decrypt this message
	UsrSymmetricKey - The decryption key held by the user is encrypted in the DB. This is the key to decrypt that master key
	Level - The encryption Level we are decoding at this step
*/

type DecryptOptions struct {
	Data            string
	Usr             *models.User
	UsrSymmetricKey string
	Level           string
}

type Crypto interface {
	/*
		Encrypt the message with the shared public key at the owner level
	*/
	EncryptOwnerLevel(data string) (string, error)
	/*
		Decrypt a message using the passed options
	*/
	DecryptMessage(opt *DecryptOptions) (string, error)
	/*
		PasswordDerivation - Derive a token from a password and a salt using bcrypt
	*/
	PasswordDerivation(password string, salt string) (string, error)
	GenerateSalt() string
}

type CryptoProvider struct {
}

func (c CryptoProvider) Provide() Crypto {
	keyRepository := di.Get[repository.KeyRepository]()
	var instance Crypto = &crypto{keyRepository}
	return instance
}

func (c *crypto) EncryptOwnerLevel(data string) (string, error) {
	publicKey := c.keyRepository.GetPublicKey(keyType.OWNER_PUBLIC_KEY)
	if publicKey == nil {
		return "", lib.Error{Msg: "No owner public key found"}
	}

	encryptedBytes, err := eciesgo.Encrypt(publicKey.PublicKey.Key, []byte(data))
	return string(encryptedBytes), err
}

func (c *crypto) DecryptMessage(opt *DecryptOptions) (string, error) {
	// TODO: Get the appropriate Level key
	privateKey, err := opt.Usr.EncryptionKey.PrivateKey.Key(opt.UsrSymmetricKey)
	if err != nil {
		return "", err
	}

	decryptedBytes, err := eciesgo.Decrypt(privateKey, []byte(opt.Data))
	return string(decryptedBytes), err
}

func (c *crypto) PasswordDerivation(password string, salt string) (string, error) {
	saltedPassword := password + salt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), bcrypt.DefaultCost)
	return string(hashedPassword), err
}

func (c *crypto) GenerateSalt() string {
	saltBytes := make([]byte, constants.SaltSize)

	for i := range saltBytes {
		saltBytes[i] = constants.LetterBytes[rand.Intn(len(constants.LetterBytes))]
	}
	return string(saltBytes)
}
