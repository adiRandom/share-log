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
	SaveAll(model []T) error
	GetById(id uint) *T
	Count() (int64, error)
	Delete(entity *T) error
	DeletePermanently(entity *T) error
	BatchDeletePermanently(entities []T) error
}

func newBaseRepository[T any](db *gorm.DB) baseRepository[T] {
	return baseRepository[T]{db: db}
}

/*
Save saves an entity to the database
The id of the entity is set by the database on the object passed in
*/

func (r *baseRepository[T]) Save(model *T) error {
	return r.db.Save(model).Error
}

func (r *baseRepository[T]) SaveAll(models []T) error {
	for _, model := range models {
		err := r.Save(&model)
		if err != nil {
			return err
		}
	}

	return nil
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

func (r *baseRepository[T]) Delete(entity *T) error {
	db := r.getDb()
	return db.Delete(&entity).Error
}

func (r *baseRepository[T]) DeletePermanently(entity *T) error {
	db := r.getDb()
	return db.Unscoped().Delete(&entity).Error
}

func (r *baseRepository[T]) BatchDeletePermanently(entities []T) error {
	db := r.getDb()
	return db.Unscoped().Delete(entities).Error
}
