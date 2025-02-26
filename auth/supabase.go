package auth

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/supabase-community/postgrest-go"
)

// supabaseClient implements the SupabaseClient interface
type supabaseClient struct {
	*postgrest.Client
}

func (s *supabaseClient) From(table string) *postgrest.QueryBuilder {
	return s.Client.From(table)
}

// InitSupabaseClient creates and configures a Supabase client
func InitSupabaseClient(url string, anonKey string) (SupabaseClient, error) {
	if url == "" {
		url = os.Getenv("SUPABASE_URL")
	}
	if anonKey == "" {
		anonKey = os.Getenv("SUPABASE_ANON_KEY")
	}

	if url == "" || anonKey == "" {
		return nil, NewAuthError(400, "InitSupabaseClient", "Supabase URL or anon key not set", "", "", nil)
	}

	client := postgrest.NewClient(url, "", map[string]string{
		"apikey":        anonKey,
		"Authorization": "Bearer " + anonKey,
	})

	return &supabaseClient{client}, nil
}

// SubscriberInfo represents a row in our active_subscribers table
type SubscriberInfo struct {
	UUID     string   `json:"uuid"`
	Tier     Tier     `json:"tier"`
	Status   Status   `json:"status"`
	Email    string   `json:"email"`
	Features Features `json:"features"`
}

// SupabaseUserRepository implements the UserRepository interface
type SupabaseUserRepository struct {
	client SupabaseClient
	logger *log.Logger
}

func NewSupabaseUserRepository(client SupabaseClient, logger *log.Logger) (*SupabaseUserRepository, error) {
	if client == nil {
		return nil, NewAuthError(400, "NewSupabaseUserRepository", "Supabase client cannot be nil", "", "", nil)
	}

	if logger == nil {
		logger = log.New(os.Stdout, "[SUPABASE-REPO] ", log.LstdFlags)
	}

	logger.Printf("Initializing Supabase user repository")

	return &SupabaseUserRepository{
		client: client,
		logger: logger,
	}, nil
}

func executeWithContext[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	var zero T

	resultCh := make(chan struct {
		value T
		err   error
	}, 1)

	go func() {
		value, err := operation()

		select {
		case resultCh <- struct {
			value T
			err   error
		}{value, err}:
		case <-ctx.Done():
			// Context was canceled, just return
			return
		}
	}()

	select {
	case result := <-resultCh:
		return result.value, result.err
	case <-ctx.Done():
		return zero, fmt.Errorf("operation canceled: %w", ctx.Err())
	}
}

func (r *SupabaseUserRepository) GetAllUserIDs(ctx context.Context) ([]string, error) {
	r.logger.Printf("Starting GetAllUserIDs request")

	return executeWithContext(ctx, func() ([]string, error) {
		var userIDs []string

		r.logger.Printf("Building query for users table")

		// Only select the UUID field
		query := r.client.From("users").
			Select("uuid", "", false)

		_, err := query.ExecuteTo(&userIDs)

		if err != nil {
			r.logger.Printf("Error executing query: %v", err)
			return nil, fmt.Errorf("failed to get all user IDs: %w", err)
		}

		r.logger.Printf("Successfully retrieved %d user IDs", len(userIDs))
		return userIDs, nil
	})
}

func (r *SupabaseUserRepository) GetUserByID(ctx context.Context, userID string) (*UserData, error) {
	if userID == "" {
		return nil, NewKeyNotFoundError("user", "empty-id", nil)
	}

	r.logger.Printf("Starting GetUserByID request for user: %s", userID)

	return executeWithContext(ctx, func() (*UserData, error) {
		var subscriber SubscriberInfo

		count, err := r.client.From("active_subscribers").
			Select("uuid, tier, status, email, features", "", false).
			Eq("uuid", userID).
			Eq("status", "active").
			Single().
			ExecuteTo(&subscriber)

		if err != nil {
			r.logger.Printf("Error executing query: %v", err)
			return nil, fmt.Errorf("failed to get user %s: %w", userID, err)
		}

		if count == 0 {
			r.logger.Printf("No active subscriber found for user ID: %s", userID)
			return nil, NewKeyNotFoundError("user", userID, nil)
		}

		tier := subscriber.Tier

		userData := &UserData{
			ID:       subscriber.UUID,
			Tier:     tier,
			Email:    subscriber.Email,
			Status:   Status(subscriber.Status),
			Features: make(map[string]map[string]map[string]string),
		}

		r.logger.Printf("Successfully retrieved user data: %+v", userData)
		return userData, nil
	})
}

func (r *SupabaseUserRepository) GetSubscribedUsers(ctx context.Context) ([]UserData, error) {
	r.logger.Printf("Starting GetSubscribedUsers request")

	return executeWithContext(ctx, func() ([]UserData, error) {
		var subscribers []SubscriberInfo

		query := r.client.From("active_subscribers").
			Select("uuid, email, tier, features", "", false).
			Eq("status", "active")

		count, err := query.ExecuteTo(&subscribers)
		if err != nil {
			r.logger.Printf("Error getting subscribers: %v", err)
			return nil, fmt.Errorf("failed to get subscribed users: %w", err)
		}

		r.logger.Printf("Retrieved %d subscriber records", count)

		userData := make([]UserData, 0, len(subscribers))
		for _, sub := range subscribers {
			tier := sub.Tier
			user := UserData{
				ID:       sub.UUID,
				Tier:     tier,
				Email:    sub.Email,
				Status:   Status(sub.Status),
				Features: make(map[string]map[string]map[string]string),
			}
			userData = append(userData, user)
		}

		r.logger.Printf("Processed %d subscribers", len(userData))
		return userData, nil
	})
}
