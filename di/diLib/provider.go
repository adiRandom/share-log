package diLib

const SingletonProvider = "singleton"
const FactoryProvider = "factory"

type ProviderType string

type Provider[T any] interface {
	Provide() T
}

type storedProvider struct {
	provider     interface{}
	providerType ProviderType
}
