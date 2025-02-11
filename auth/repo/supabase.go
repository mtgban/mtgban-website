package repo

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/mtgban/mtgban-website/auth/models"
	"github.com/supabase-community/postgrest-go"
)

// supabaseClientWrapper implements the SupabaseClient interface
type supabaseClientWrapper struct {
	*postgrest.Client
}

func (s *supabaseClientWrapper) From(table string) *postgrest.QueryBuilder {
	return s.Client.From(table)
}

func (s *supabaseClientWrapper) DB() *postgrest.QueryBuilder {
	return s.Client.From("")
}

// InitSupabaseClient creates and configures a Supabase client
func InitSupabaseClient(url, anonKey string) SupabaseClient {
	if url == "" {
		log.Fatal("SUPABASE_URL environment variable is not set")
	}
	if anonKey == "" {
		log.Fatal("SUPABASE_ANON_KEY environment variable is not set")
	}

	client := postgrest.NewClient(url, "", map[string]string{
		"apikey":        anonKey,
		"Authorization": "Bearer " + anonKey,
	})

	return &supabaseClientWrapper{client}
}

// SubscriberInfo represents a row in our active_subscribers table
type SubscriberInfo struct {
	UUID        string `json:"uuid"`
	ProductName string `json:"product_name"`
	Status      string `json:"status"`
}

// SupabaseUserRepository implements the UserRepository interface
type SupabaseUserRepository struct {
	client SupabaseClient
}

func NewSupabaseUserRepository(client SupabaseClient) *SupabaseUserRepository {
	return &SupabaseUserRepository{client: client}
}

func (r *SupabaseUserRepository) GetUserByID(ctx context.Context, userID string) (*models.UserData, error) {
	var userData models.UserData

	type result struct {
		user *models.UserData
		err  error
	}
	done := make(chan result, 1)

	go func() {
		count, err := r.client.From("users").
			Select("id, role, created_at, last_sign_in", "", false).
			Eq("id", userID).
			Single().
			ExecuteTo(&userData)

		if err != nil {
			done <- result{nil, fmt.Errorf("failed to get user %s: %w", userID, err)}
			return
		}

		if count == 0 {
			done <- result{nil, nil}
			return
		}

		done <- result{&userData, nil}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled or timed out: %w", ctx.Err())
	case res := <-done:
		return res.user, res.err
	}
}

func (r *SupabaseUserRepository) GetModifiedUsersSince(ctx context.Context, since time.Time) ([]models.UserData, error) {
	var modifiedUsers []models.UserData

	type result struct {
		users []models.UserData
		err   error
	}
	done := make(chan result, 1)

	go func() {
		_, err := r.client.From("users").
			Select("id, role, created_at, last_sign_in", "", false).
			Gte("last_sign_in", since.Format(time.RFC3339)).
			ExecuteTo(&modifiedUsers)

		if err != nil {
			done <- result{nil, fmt.Errorf("failed to get modified users since %s: %w", since, err)}
			return
		}
		done <- result{modifiedUsers, nil}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled or timed out: %w", ctx.Err())
	case res := <-done:
		return res.users, res.err
	}
}

func (r *SupabaseUserRepository) GetAllUserIDs(ctx context.Context) ([]string, error) {
	var allUserIDs []string

	type result struct {
		ids []string
		err error
	}
	done := make(chan result, 1)

	go func() {
		_, err := r.client.From("users").
			Select("id", "", false).
			ExecuteTo(&allUserIDs)

		if err != nil {
			done <- result{nil, fmt.Errorf("failed to get all user IDs: %w", err)}
			return
		}
		done <- result{allUserIDs, nil}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled or timed out: %w", ctx.Err())
	case res := <-done:
		return res.ids, res.err
	}
}

func (r *SupabaseUserRepository) GetSubscribedUsers(ctx context.Context) ([]models.UserData, error) {
	var subscribers []SubscriberInfo

	type result struct {
		users []models.UserData
		err   error
	}
	done := make(chan result, 1)

	go func() {
		_, err := r.client.From("active_subscribers").
			Select("uuid, product_name, status", "", false).
			ExecuteTo(&subscribers)

		if err != nil {
			done <- result{nil, fmt.Errorf("failed to get subscribed users: %w", err)}
			return
		}

		userData := make([]models.UserData, len(subscribers))
		for i, sub := range subscribers {
			userData[i] = models.UserData{
				ID:     sub.UUID,
				Role:   models.UserRole(sub.ProductName).FromProductName(sub.ProductName),
				Status: sub.Status,
			}
		}

		done <- result{userData, nil}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled or timed out: %w", ctx.Err())
	case res := <-done:
		return res.users, res.err
	}
}
