package interfaces

import (
	"shareLog/data/repository"
	"shareLog/models"
)

type LogRepository interface {
	repository.BaseRepository[models.Log]
}
