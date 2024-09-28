package encryption

import (
	"shareLog/lib"
)

type SymmetricKey struct {
	encryptedString *string
	decryptedString *string
	encryptionIv    *string
}

func (s *SymmetricKey) Decrypt(passphrase string) error {
	if s == nil || s.encryptedString == nil || s.encryptionIv == nil {
		return lib.Error{Msg: "Invalid symmetric key"}
	}

	decryptedString, err := lib.PerformSymmetricDecryption(*s.encryptedString, lib.AesKeyLength, *s.encryptionIv, []byte(passphrase))
	if err != nil {
		return err
	}

	s.decryptedString = &decryptedString
	return nil
}

// Encrypt This will overwrite previous encryption params
func (s *SymmetricKey) Encrypt(passphrase string) (*string, error) {
	if s == nil || s.decryptedString == nil {
		return nil, lib.Error{Msg: "Invalid symmetric key"}
	}

	encryptedString, iv, err := lib.PerformSymmetricEncryption(*s.decryptedString, []byte(passphrase))
	if err != nil {
		return nil, err
	}

	s.encryptionIv = &iv
	s.encryptedString = &encryptedString
	return &encryptedString, nil
}
