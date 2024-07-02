package services

import (
	"errors"
	eciesgo "github.com/ecies/go/v2"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"shareLog/constants"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/models"
	"shareLog/models/encryption"
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
	/*
		Extract from the JWE the encryption key of the user that crated the invite

		@param inviteJWE: The JWE that contains the user id of the user that created the invite, the access Level
		and the key to decrypt the master key for that access Level

		@param encryptionKey: The key used to encrypt the master private key for the new user
		@return The encryption key of the user that created the invite
	*/
	GetEncryptionKeyForNewUser(inviteJWE string, encryptionKey string) (*encryption.EncryptionKey, error)
	DecodeJWE(jwe *jose.JSONWebEncryption) *jwt.Token
}

type CryptoProvider struct {
}

func (c CryptoProvider) Provide() Crypto {
	keyRepository := di.Get[repository.KeyRepository]()
	var instance Crypto = &crypto{keyRepository}
	return instance
}

func (c *crypto) EncryptOwnerLevel(data string) (string, error) {
	publicKey := c.keyRepository.GetSharedDataOwnerPublicKey().PublicKey
	encryptedBytes, err := eciesgo.Encrypt(publicKey.Key, []byte(data))
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

/*
getSharedKey - Get the shared key for this user from the invite JWE
*/
func (c *crypto) getSharedKey(inviteJwe string) (encryption.EncryptionKey, error) {
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
	saltBytes := make([]byte, constants.SaltSize)

	for i := range saltBytes {
		saltBytes[i] = constants.LetterBytes[rand.Intn(len(constants.LetterBytes))]
	}
	return string(saltBytes)
}

func (c *crypto) GetEncryptionKeyForNewUser(inviteJWE string, encryptionKey string) (*encryption.EncryptionKey, error) {
	masterKey, err := c.getSharedKey(inviteJWE)
	if err != nil {
		return nil, err
	}

	// TODO: Encrypt the key and save it in the db
	return &masterKey, nil
}

func (c *crypto) DecodeJWE(jwe *jose.JSONWebEncryption) *jwt.Token {
	key := c.keyRepository.GetJWEDecryptKey()
	jwtBytes, err := jwe.Decrypt(key)
	if err != nil {
		println(err)
		return nil
	}

	token, _ := jwt.Parse(string(jwtBytes), nil)
	return token
}
