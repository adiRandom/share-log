package di

import (
	"shareLog/data/repository"
	"shareLog/data/repository/interfaces"
)

type LogRepositoryProvider struct {
}

func (p LogRepositoryProvider) Provide() interfaces.LogRepository {
	return repository.NewLogRepository()
}
