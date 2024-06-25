package lib

func IsOfType[T any](any interface{}) bool {
	_, isType := any.(T)
	return isType
}
