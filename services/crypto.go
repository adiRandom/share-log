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
	DeriveSecurePassphrase(password string, salt string) []byte
	CreateFirstEncryptionKey(t userGrant.Type, userSymmetricKey string) (*encryption.Key, error)
	CreateEncryptionKey(key *eciesgo.PrivateKey, t userGrant.Type, userSymmetricKey string) (*encryption.Key, error)
	CreateJwe(token *jwtLib.Token) (*jose.JSONWebEncryption, error)
	/*
		Return the signed string representing the underlying JWT
	*/
	DecodeJwe(serializedJwe string) (string, error)
	GenerateUserSymmetricKey() string
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
	key := lib.Find(opt.Usr.EncryptionKeys, func(key encryption.Key) bool {
		return key.UserGrant == opt.Level
	})
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

func (c *crypto) CreateEncryptionKey(key *eciesgo.PrivateKey, t userGrant.Type, userSymmetricKey string) (*encryption.Key, error) {
	hex := key.Hex()
	encryptedHex, iv, err := lib.PerformSymmetricEncryption(hex, []byte(userSymmetricKey))
	if err != nil {
		return nil, err
	}

	privateKey := encryption.NewEncryptionKey(key.PublicKey, encryptedHex, iv, t)

	return &privateKey, nil
}

func (c *crypto) CreateFirstEncryptionKey(t userGrant.Type, userSymmetricKey string) (*encryption.Key, error) {
	key, err := eciesgo.GenerateKey()
	if err != nil {
		return nil, err
	}
	return c.CreateEncryptionKey(key, t, userSymmetricKey)
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

	parsed, err := jwtLib.ParseWithClaims(signedToken, jwtClaims{}, func(t *jwtLib.Token) (interface{}, error) { return c.keyRepository.GetJWTPubKey() })
	parsedClaims := parsed.Claims.(jwtClaims).SymmetricKey
	print(parsedClaims)

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

func (c *crypto) GenerateUserSymmetricKey() string {
	return lib.GetRandomString(lib.AesKeyLength)
}
