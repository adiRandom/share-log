package di

import (
	"shareLog/di/diLib"
)

var Container = diLib.NewContainer()

func Get[T any]() T {
	return diLib.Get[T](Container)
}

func GetAll[T any]() []T {
	return diLib.GetAll[T](Container)
}
