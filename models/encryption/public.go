package encryption

import (
	"database/sql/driver"
	"errors"
	eciesgo "github.com/ecies/go/v2"
)

type PublicKey struct {
	Key *eciesgo.PublicKey
}

func (p *PublicKey) Scan(src any) error {
	hex, ok := src.(string)
	if !ok {
		return errors.New("public key must be a string")
	}

	key, err := eciesgo.NewPublicKeyFromHex(hex)
	if err != nil {
		return err
	}

	*p = PublicKey{key}
	return nil
}

func (p *PublicKey) Value() (driver.Value, error) {
	if p == nil || p.Key == nil {
		return nil, nil
	}

	return p.Key.Hex(false), nil
}

func (p *PublicKey) GormDataType() string {
	return "text"
}
