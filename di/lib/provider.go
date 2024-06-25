package lib

type Provider[T any] interface {
	Provide() T
}
