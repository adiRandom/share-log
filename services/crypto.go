package services

import (
	"crypto/rand"
	"crypto/sha256"
	eciesgo "github.com/ecies/go/v2"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
	"shareLog/constants"
	"shareLog/data/repository"
	"shareLog/di"
	"shareLog/lib"
	"shareLog/models"
	"shareLog/models/encryption"
	"shareLog/models/userGrant"
)

const derivePasswordHashIter = 32
const derivePasswordKeyLen = 32

type crypto struct {
	keyRepository repository.KeyRepository
}

/*
	Options used to decrypt a message

	Data - The message to decrypt
	Usr - The userGrant that has a key that can be used to decrypt this message
	UsrSymmetricKey - The decryption key held by the userGrant is encrypted in the DB. This is the key to decrypt that master key
	Level - The encryption Level we are decoding at this step
*/

type DecryptOptions struct {
	Data            string
	Usr             *models.User
	UsrSymmetricKey string
	Level           userGrant.Type
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
	GenerateSalt() string
	CreateEncryptionKey(key *eciesgo.PrivateKey, t userGrant.Type, passphrase string, salt string) (*encryption.PrivateKey, error)
}

type CryptoProvider struct {
}

func (c CryptoProvider) Provide() any {
	keyRepository := di.Get[repository.KeyRepository]()
	var instance Crypto = &crypto{keyRepository}
	return instance
}

func (c *crypto) EncryptOwnerLevel(data string) (string, error) {
	publicKey := c.keyRepository.GetPublicKey(userGrant.GRANT_OWNER)
	if publicKey == nil {
		return "", lib.Error{Msg: "No owner public key found"}
	}

	encryptedBytes, err := eciesgo.Encrypt(publicKey.PublicKey.Key, []byte(data))
	return string(encryptedBytes), err
}

func (c *crypto) DecryptMessage(opt *DecryptOptions) (string, error) {
	// TODO: Get the appropriate Level key
	privateKey, err := opt.Usr.EncryptionKey.PrivateKey.Key([]byte(opt.UsrSymmetricKey))
	if err != nil {
		return "", err
	}

	decryptedBytes, err := eciesgo.Decrypt(privateKey, []byte(opt.Data))
	return string(decryptedBytes), err
}

func (c *crypto) passwordDerivation(password string, salt string) []byte {
	return pbkdf2.Key([]byte(password), []byte(salt), derivePasswordHashIter, derivePasswordKeyLen, sha256.New)
}

func (c *crypto) GenerateSalt() string {
	saltBytes := make([]byte, constants.SaltSize)
	maxRndInt := big.NewInt(int64(len(constants.LetterBytes)))

	for i := range saltBytes {
		randomInt, _ := rand.Int(rand.Reader, maxRndInt)
		saltBytes[i] = constants.LetterBytes[randomInt.Int64()]
	}
	return string(saltBytes)
}

func (c *crypto) CreateEncryptionKey(key *eciesgo.PrivateKey, t userGrant.Type, passphrase string, salt string) (*encryption.PrivateKey, error) {
	hex := key.Hex()
	hashedPassphrase := c.passwordDerivation(passphrase, salt)
	encryptedHex, iv, err := lib.PerformSymmetricEncryption(hex, hashedPassphrase)
	if err != nil {
		return nil, err
	}

	privateKey := encryption.NewEncryptionKey(key.PublicKey, encryptedHex, iv, t)
	err = c.keyRepository.Save(&privateKey)
	if err != nil {
		return nil, err
	}

	return privateKey.PrivateKey, nil
}
