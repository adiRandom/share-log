package encryption

import (
	"database/sql/driver"
	"errors"
	eciesgo "github.com/ecies/go/v2"
)

type PrivateKey struct {
	hex string
}

func (k *PrivateKey) Key() (*eciesgo.PrivateKey, error) {
	// TODO: Decrypt the hex and convert it to a private key
	return eciesgo.NewPrivateKeyFromHex(k.hex)
}

func (k *PrivateKey) Scan(src any) error {
	hex, ok := src.(string)
	if !ok {
		return errors.New("private key must be a string")
	}

	*k = PrivateKey{hex: hex}
	return nil
}

func (k *PrivateKey) Value() (driver.Value, error) {
	return k.hex, nil
}

func (p *PrivateKey) GormDataType() string {
	return "text"
}
