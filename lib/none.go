package lib

type None struct {
}

func IsNone(any interface{}) bool {
	_, isNon := any.(None)
	return isNon
}
