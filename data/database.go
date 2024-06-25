package data

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"shareLog/models"
)

type DatabaseProvider struct {
}

func (d DatabaseProvider) Provide() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Run migrations
	err = db.AutoMigrate(getMigrations()...)
	if err != nil {
		return nil
	}

	return db
}

func getMigrations() []interface{} {
	return []interface{}{
		&models.Log{},
	}
}
