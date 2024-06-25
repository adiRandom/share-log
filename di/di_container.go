package di

import (
	"shareLog/di/lib"
)

var Container = lib.NewContainer()

func Get[T any]() T {
	return lib.Get[T](Container)
}
