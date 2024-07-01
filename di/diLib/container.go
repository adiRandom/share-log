package diLib

type Container struct {
	store []interface{}
	// Holds slice of Provider
	providers []storedProvider
}

func NewContainer() *Container {
	return &Container{}
}

func RegisterProvider[Type any](c *Container, provider Provider[Type], providerType ProviderType) {
	opaqueProvider, _ := provider.(interface{})
	providerToStore := storedProvider{
		provider:     opaqueProvider,
		providerType: providerType,
	}
	c.providers = append(c.providers, providerToStore)
}

func Get[Type any](c *Container) Type {
	for _, instance := range c.store {
		if casted, ok := (instance).(Type); ok {
			return casted
		}
	}

	// No instance found, create a new one
	for _, provider := range c.providers {
		if casted, ok := (provider.provider).(Provider[Type]); ok {
			instance := casted.Provide()
			shouldStore := provider.providerType == SingletonProvider

			if shouldStore {
				c.store = append(c.store, instance)
			}
			return instance
		}
	}

	panic("No provider found for type")
}
