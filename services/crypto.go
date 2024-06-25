package services

type crypto struct {
}

type Crypto interface {
	EncryptOwnerLevel(data string) (string, error)
}

type CryptoProvider struct {
}

func (c CryptoProvider) Provide() Crypto {
	var instance Crypto = crypto{}
	return instance
}

func (c crypto) EncryptOwnerLevel(data string) (string, error) {
	return data, nil
}
