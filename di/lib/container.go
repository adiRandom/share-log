package lib

type Container struct {
	store []interface{}
	// Holds slice of Provider
	providers []interface{}
}

func NewContainer() *Container {
	return &Container{}
}

func RegisterProvider[Type any](c *Container, provider Provider[Type]) {
	opaqueProvider, _ := provider.(interface{})
	c.providers = append(c.providers, opaqueProvider)
}

func Get[Type any](c *Container) Type {
	for _, instance := range c.store {
		if casted, ok := (instance).(Type); ok {
			return casted
		}
	}

	// No instance found, create a new one
	for _, provider := range c.providers {
		if casted, ok := (provider).(Provider[Type]); ok {
			instance := casted.Provide()
			c.store = append(c.store, instance)
			return instance
		}
	}

	panic("No provider found for type")
}
