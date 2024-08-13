package data

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"shareLog/models"
	"shareLog/models/encryption"
)

type DatabaseProvider struct {
}

func (d DatabaseProvider) Provide() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Run migrations
	err = db.AutoMigrate(getEntities()...)
	if err != nil {
		return nil
	}

	return db
}

func getEntities() []interface{} {
	return []interface{}{
		&models.Log{},
		&encryption.Key{},
		&models.User{},
	}
}
