package repo

import (
	"context"
	"time"

	"github.com/mtgban/mtgban-website/auth/models"
	"github.com/supabase-community/postgrest-go"
)

type SupabaseClient interface {
	From(table string) *postgrest.QueryBuilder
	DB() *postgrest.QueryBuilder
}

type UserRepository interface {
	GetUserByID(ctx context.Context, id string) (*models.UserData, error)
	GetModifiedUsersSince(ctx context.Context, time time.Time) ([]models.UserData, error)
	GetAllUserIDs(ctx context.Context) ([]string, error)
	GetSubscribedUsers(ctx context.Context) ([]models.UserData, error)
}
