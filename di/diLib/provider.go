package diLib

const SingletonProvider = "singleton"
const FactoryProvider = "factory"

type ProviderType string

type Provider interface {
	Provide() any
}

type storedProvider struct {
	provider        Provider
	providerType    ProviderType
	bindings        []interface{}
	registeredType  any
	storedInstances *any
}

type typeInfo[T any] struct {
}

func (p *storedProvider) GetOrCreateInstance() any {
	if p.providerType == SingletonProvider {
		instance := p.storedInstances
		if instance == nil {
			newInstance := p.provider.Provide()
			instance = &newInstance
			p.storedInstances = instance
		}

		return instance
	} else {
		return p.provider.Provide()
	}
}

type Binding[T any] struct {
}
