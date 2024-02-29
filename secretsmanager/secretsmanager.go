package secretsmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"golang.org/x/oauth2/google"
)

type SecretInfo struct {
	Name      string `json:"name"`
	Version   int    `json:"version"`
	MountPath string `json:"mount_path"`
}

type ServiceAccountCredentials struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

func RetrieveSecretAsString(ctx context.Context, secretID string) (string, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create secret manager client: %w", err)
	}
	defer client.Close()

	request := &secretmanagerpb.AccessSecretVersionRequest{Name: secretID}
	result, err := client.AccessSecretVersion(ctx, request)
	if err != nil {
		return "", fmt.Errorf("failed to access secret version '%s': %w", secretID, err)
	}

	secretValue := string(result.Payload.Data)
	return secretValue, nil
}

func FetchServiceAccountCredentials(ctx context.Context, secretID string) (*ServiceAccountCredentials, error) {
	secretValue, err := RetrieveSecretAsString(ctx, secretID)
	if err != nil {
		return nil, err
	}

	var credentials ServiceAccountCredentials
	if err := json.Unmarshal([]byte(secretValue), &credentials); err != nil {
		return nil, fmt.Errorf("failed to unmarshal service account credentials: %w", err)
	}
	return &credentials, nil
}

func CreateAuthenticatedClient(ctx context.Context, projectID string, serviceAccount SecretInfo) (*google.Credentials, error) {
	if serviceAccount.Name == "" {
		return nil, fmt.Errorf("service account name is empty")
	}
	if serviceAccount.Version == 0 {
		return nil, fmt.Errorf("service account version is empty")
	}
	if serviceAccount.MountPath == "" {
		log.Printf("service account mount path is empty")
	}
	secretID := fmt.Sprintf("projects/%s/secrets/%s/versions/%d", projectID, serviceAccount.Name, serviceAccount.Version)
	credentials, err := FetchServiceAccountCredentials(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch service account credentials: %v", err)
	}

	jsonCredentials, err := json.Marshal(credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credentials to JSON: %v", err)
	}

	googleCredentials, err := google.CredentialsFromJSON(ctx, jsonCredentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Google credentials from JSON: %v", err)
	}
	return googleCredentials, nil
}
