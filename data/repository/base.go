package repository

import (
	"fmt"
	"gorm.io/gorm"
)

type baseRepository[T any] struct {
	db *gorm.DB
}

type BaseRepository[T any] interface {
	getDb() *gorm.DB
	Save(model *T) error
	GetById(id uint) *T
	Count() (int64, error)
}

func newBaseRepository[T any](db *gorm.DB) baseRepository[T] {
	return baseRepository[T]{db: db}
}

/*
Create saves an entity to the database
The id of the entity is set by the database on the object passed in
*/
func (r *baseRepository[T]) Save(model *T) error {
	return r.db.Create(model).Error
}

func (r *baseRepository[T]) getDb() *gorm.DB {
	return r.db
}

func (r *baseRepository[T]) GetById(id uint) *T {
	db := r.getDb()
	var result T
	err := db.First(&result, id).Error

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return &result
}

func (r *baseRepository[T]) Count() (int64, error) {
	db := r.getDb()
	var result int64
	var model T
	err := db.Model(&model).Count(&result).Error

	if err != nil {
		return 0, err
	}

	return result, nil
}
