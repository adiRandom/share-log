package encryption

import (
	eciesgo "github.com/ecies/go/v2"
	"shareLog/lib"
)

const keySize = 64 // bytes

type PrivateKey struct {
	EncryptedHex string
	Iv           string
}

func (k *PrivateKey) Key(userSymmetricKey []byte) (*eciesgo.PrivateKey, error) {
	decryptedHex, err := lib.PerformSymmetricDecryption(
		k.EncryptedHex,
		keySize,
		k.Iv,
		userSymmetricKey,
	)

	if err != nil {
		return nil, err
	}
	return eciesgo.NewPrivateKeyFromHex(decryptedHex)
}

func NewPrivateKeyFromHex(encryptedHex string, iv string) (*PrivateKey, error) {
	return &PrivateKey{EncryptedHex: encryptedHex, Iv: iv}, nil
}
