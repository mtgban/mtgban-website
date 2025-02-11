package service

import (
	"context"
	"fmt"
	"time"

	"github.com/mtgban/mtgban-website/auth/cache"
	"github.com/mtgban/mtgban-website/auth/models"
)

func (s *AuthService) backgroundRefresh() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.config.Auth.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.refreshCache(context.Background()); err != nil {
				s.logger.Printf("Background refresh failed: %v", err)
			}
		case <-s.shutdown:
			return
		}
	}
}

func (s *AuthService) refreshCache(ctx context.Context) error {
	// Get current cache state
	currentUsers := s.cache.GetAllUsers()

	// Fetch all current valid user IDs
	allUserIDs, err := s.repo.GetAllUserIDs(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch user IDs: %w", err)
	}

	// Check context after expensive DB call
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error after fetching IDs: %w", err)
	}

	// Create map of valid users for O(1) lookup
	validUsers := make(map[string]struct{}, len(allUserIDs))
	for _, id := range allUserIDs {
		validUsers[id] = struct{}{}
	}

	// Track changes for atomicity
	updates := make(map[string]*models.UserData)
	deletions := make([]string, 0)

	// Find users to delete (in cache but not in DB)
	for userID := range currentUsers {
		if _, exists := validUsers[userID]; !exists {
			deletions = append(deletions, userID)
		}
	}

	// Find users to update (in DB)
	for _, userID := range allUserIDs {
		userData, err := s.repo.GetUserByID(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to fetch user %s: %w", userID, err)
		}
		updates[userID] = userData
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error before applying changes: %w", err)
	}

	for userID := range updates {
		s.cache.SetUser(updates[userID])
	}
	for _, userID := range deletions {
		s.cache.DeleteUser(userID)
	}

	if c, ok := s.cache.(*cache.UserCache); ok {
		c.UpdateLastSync()
	}

	s.logger.Printf("Cache refresh completed: updated %d users, removed %d users",
		len(updates), len(deletions))
	return nil
}
