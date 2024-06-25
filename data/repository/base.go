package repository

import "gorm.io/gorm"

type baseRepository[T any] struct {
	db *gorm.DB
}

type BaseRepository[T any] interface {
	getDb() *gorm.DB
	Create(model *T) error
}

func newBaseRepository[T any](db *gorm.DB) baseRepository[T] {
	return baseRepository[T]{db: db}
}

/*
Create saves an entity to the database
The id of the entity is set by the database on the object passed in
*/
func (r *baseRepository[T]) Create(model *T) error {
	return r.db.Create(model).Error
}

func (r *baseRepository[T]) getDb() *gorm.DB {
	return r.db
}
