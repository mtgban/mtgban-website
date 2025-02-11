package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/mtgban/mtgban-website/auth/cache"
	"github.com/mtgban/mtgban-website/auth/models"
	"github.com/mtgban/mtgban-website/auth/repo"
)

type AuthService struct {
	client   repo.SupabaseClient
	repo     repo.UserRepository
	cache    cache.Cache
	logger   *log.Logger
	config   *models.AuthConfig
	shutdown chan struct{}
	wg       sync.WaitGroup
}

func NewAuthService(client repo.SupabaseClient, config *models.AuthConfig, logger *log.Logger) (*AuthService, error) {
	if config == nil {
		config = &models.AuthConfig{}
	}

	jwtSecret := os.Getenv("SUPABASE_JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("SUPABASE_JWT_SECRET environment variable is not set")
	}

	config.Auth.WebhookSecretKey = jwtSecret
	if logger == nil {
		logger = log.New(os.Stdout, "[AUTH] ", log.LstdFlags)
	}

	cache := cache.NewCache(cache.DefaultCacheOptions())
	repo := repo.NewSupabaseUserRepository(client)

	service := &AuthService{
		client:   client,
		repo:     repo,
		cache:    cache,
		logger:   logger,
		config:   config,
		shutdown: make(chan struct{}),
	}

	// Initial cache load
	if err := service.cache.LoadInitialData(context.Background(), service.repo); err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Start background refresh if interval is set
	if config.Auth.RefreshInterval > 0 {
		service.wg.Add(1)
		go service.backgroundRefresh()
	}

	return service, nil
}

func (s *AuthService) Shutdown(ctx context.Context) error {
	s.logger.Printf("Initiating graceful shutdown")
	close(s.shutdown)

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Printf("Graceful shutdown completed")
		return nil
	case <-ctx.Done():
		return fmt.Errorf("shutdown context expired: %w", ctx.Err())
	}
}

func (s *AuthService) HasRequiredRole(role, requiredRole models.UserRole) bool {
	// Admin has all permissions
	if role == models.RoleAdmin {
		return true
	}

	// Direct match
	if role == requiredRole {
		return true
	}

	// Check inherited roles
	allowedRoles, exists := models.RoleHierarchy[role]
	if !exists {
		return false
	}

	for _, r := range allowedRoles {
		if r == requiredRole {
			return true
		}
	}
	return false
}
