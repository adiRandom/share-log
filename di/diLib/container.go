package diLib

type Container struct {
	providers []storedProvider
}

func NewContainer() *Container {
	return &Container{}
}

func RegisterProvider[Type any](c *Container, provider Provider, providerType ProviderType, bindings ...interface{}) {
	providerToStore := storedProvider{
		provider:       provider,
		providerType:   providerType,
		registeredType: typeInfo[Type]{},
		bindings:       bindings,
	}

	c.providers = append(c.providers, providerToStore)
}

func findFirstProviderForType[Type any](c *Container) *storedProvider {
	for _, provider := range c.providers {
		if isProviderForType[Type](provider) {
			return &provider
		}
	}

	return nil
}

func Get[Type any](c *Container) Type {
	provider := findFirstProviderForType[Type](c)
	if provider == nil {
		panic("No provider found for type")
	}

	instance := provider.GetOrCreateInstance()
	castedInstance, ok := instance.(Type)
	if ok {
		return castedInstance
	}

	// It is a pointer
	castedPointer, ok := instance.(*interface{})
	if ok {
		return (*castedPointer).(Type)
	}

	panic("Could not cast instance to type")
}

func isProviderForType[Type any](provider storedProvider) bool {
	var registeredType = provider.registeredType
	_, ok := registeredType.(typeInfo[Type])
	if ok {
		return true
	}

	for _, binding := range provider.bindings {
		var opaqueBinding any = binding

		if _, ok := opaqueBinding.(Binding[Type]); ok {
			return true
		}
	}

	return false
}

func GetAll[Type any](c *Container) []Type {
	var instances = make([]Type, 0)

	for _, provider := range c.providers {
		if isProviderForType[Type](provider) {
			instance := provider.GetOrCreateInstance()
			castedInstance, ok := instance.(Type)
			if ok {
				instances = append(instances, castedInstance)
				continue
			}

			// It is a pointer
			castedPointer, ok := instance.(*interface{})
			if ok {
				instances = append(instances, (*castedPointer).(Type))
				continue
			}

			panic("Could not cast instance to type")
		}
	}

	return instances
}
