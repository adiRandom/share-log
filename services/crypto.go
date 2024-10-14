package services

import (
	"crypto/rand"
	"crypto/sha256"
	eciesgo "github.com/ecies/go/v2"
	"github.com/go-jose/go-jose/v4"
	jwtLib "github.com/golang-jwt/jwt/v5"
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
*/

type DecryptOptions struct {
	Data            string
	Usr             *models.User
	UsrSymmetricKey string
	OwnerLevelKey   *encryption.Key
	ClientLevelKey  *encryption.Key
}

type Crypto interface {
	/*
		Encrypt the message with the shared public key at the owner level
	*/
	EncryptOwnerLevel(data string) (string, error)
	EncryptClientLevel(data string) (string, error)
	/*
		Decrypt a message using the passed options
	*/
	DecryptMessage(opt *DecryptOptions) (string, error)
	GenerateSalt() string
	DeriveSecurePassphrase(password string, salt string) []byte
	CreateNewEncryptionKey(t userGrant.Type, password string, salt string) (*encryption.Key, error)
	CreateEncryptionKeyWithPassword(key *eciesgo.PrivateKey, t userGrant.Type, passphrase string, salt string) (*encryption.Key, error)
	CreateEncryptionKey(key *eciesgo.PrivateKey, t userGrant.Type, symmetricKey string, salt string) (*encryption.Key, error)
	CreateJwe(token *jwtLib.Token) (*jose.JSONWebEncryption, error)
	/*
		Return the signed string representing the underlying JWT
	*/
	DecodeJwe(serializedJwe string) (string, error)
	DeriveUserSymmetricKey(password string, salt string) string
}

type CryptoProvider struct {
}

func (c CryptoProvider) Provide() any {
	keyRepository := di.Get[repository.KeyRepository]()
	var instance Crypto = &crypto{keyRepository}
	return instance
}

func (c *crypto) EncryptOwnerLevel(data string) (string, error) {
	publicKey := c.keyRepository.GetPublicKey(userGrant.Types.GrantOwner)
	if publicKey == nil {
		return "", lib.Error{Msg: "No owner public key found"}
	}

	encryptedBytes, err := eciesgo.Encrypt(publicKey.Key, []byte(data))
	return string(encryptedBytes), err
}

func (c *crypto) EncryptClientLevel(data string) (string, error) {
	publicKey := c.keyRepository.GetPublicKey(userGrant.Types.GrantClient)
	if publicKey == nil {
		return "", lib.Error{Msg: "No owner public key found"}
	}

	encryptedBytes, err := eciesgo.Encrypt(publicKey.Key, []byte(data))
	return string(encryptedBytes), err
}

func (c *crypto) DecryptMessage(opt *DecryptOptions) (string, error) {
	levels := []userGrant.Type{userGrant.Types.GrantOwner, userGrant.Types.GrantClient}
	msg := opt.Data
	for _, level := range levels {
		decryptedMsg, err := c.decryptMessageForLevel(&DecryptOptions{
			Data:            msg,
			Usr:             opt.Usr,
			UsrSymmetricKey: opt.UsrSymmetricKey,
			ClientLevelKey:  opt.ClientLevelKey,
			OwnerLevelKey:   opt.OwnerLevelKey,
		}, level)
		if err != nil {
			return "", err
		}

		msg = decryptedMsg
	}

	return msg, nil
}

func (c *crypto) decryptMessageForLevel(opt *DecryptOptions, level userGrant.Type) (string, error) {
	var key *encryption.Key
	if level == userGrant.Types.GrantOwner {
		key = opt.OwnerLevelKey
	} else if level == userGrant.Types.GrantClient {
		key = opt.ClientLevelKey
	}

	if key == nil {
		return "", lib.Error{Msg: "No valid key to decrypt message"}
	}

	privateKey, err := key.PrivateKey.Key([]byte(opt.UsrSymmetricKey))
	if err != nil {
		return "", err
	}

	decryptedBytes, err := eciesgo.Decrypt(privateKey, []byte(opt.Data))
	return string(decryptedBytes), err
}

func (c *crypto) DeriveSecurePassphrase(password string, salt string) []byte {
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

func (c *crypto) CreateEncryptionKeyWithPassword(key *eciesgo.PrivateKey, t userGrant.Type, passphrase string, salt string) (*encryption.Key, error) {
	userSymmetricKey := c.DeriveUserSymmetricKey(passphrase, salt)
	return c.CreateEncryptionKey(key, t, userSymmetricKey, salt)
}

func (c *crypto) CreateEncryptionKey(key *eciesgo.PrivateKey, t userGrant.Type, symmetricKey string, salt string) (*encryption.Key, error) {
	hex := key.Hex()
	encryptedHex, iv, err := lib.PerformSymmetricEncryption(hex, []byte(symmetricKey))
	if err != nil {
		return nil, err
	}

	privateKey := encryption.NewEncryptionKey(key.PublicKey, encryptedHex, iv, t, salt)

	return &privateKey, nil
}

func (c *crypto) CreateNewEncryptionKey(t userGrant.Type, password string, salt string) (*encryption.Key, error) {
	key, err := eciesgo.GenerateKey()
	if err != nil {
		return nil, err
	}
	return c.CreateEncryptionKeyWithPassword(key, t, password, salt)
}

func (c *crypto) CreateJwe(token *jwtLib.Token) (*jose.JSONWebEncryption, error) {
	pubKey, err := c.keyRepository.GetJwePublicKey()
	if err != nil {
		return nil, err
	}

	encrypter, err := jose.NewEncrypter(jose.A128CBC_HS256, jose.Recipient{Algorithm: jose.RSA1_5, Key: pubKey}, nil)
	if err != nil {
		return nil, err
	}

	signKey, err := c.keyRepository.GetJWTPrivateKey()
	if err != nil {
		return nil, err
	}

	signedToken, err := token.SignedString(signKey)
	if err != nil {
		return nil, err
	}

	jwe, err := encrypter.Encrypt([]byte(signedToken))
	if err != nil {
		return nil, err
	}

	return jwe, nil
}

func (c *crypto) DecodeJwe(serializedJwe string) (string, error) {
	jwe, err := jose.ParseEncryptedCompact(serializedJwe, []jose.KeyAlgorithm{jose.RSA1_5}, []jose.ContentEncryption{jose.A128CBC_HS256})
	if err != nil {
		return "", err
	}

	pk, err := c.keyRepository.GetJWEPrivateKey()
	if err != nil {
		return "", err
	}

	signedJwtBytes, err := jwe.Decrypt(pk)
	if err != nil {
		return "", err
	}

	return string(signedJwtBytes), err
}

func (c *crypto) DeriveUserSymmetricKey(password string, salt string) string {
	return string(c.DeriveSecurePassphrase(password, salt))
}
