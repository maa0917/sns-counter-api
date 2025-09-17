package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/firestore"
)

type APIKey struct {
	TenantID   string `firestore:"tenant_id"`
	Name       string `firestore:"name"`
	IgUserID   string `firestore:"ig_user_id"`
	SecretHash string `firestore:"secret_hash"`
	IsActive   bool   `firestore:"is_active"`
}

var firestoreClient *firestore.Client

func bearerTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Authorization header required",
			})
			return
		}

		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Bearer token required",
			})
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		apiKey, err := validateBearerToken(token)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid token",
			})
			return
		}

		ctx := context.WithValue(r.Context(), "tenant", apiKey)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func parseToken(token string) (tenantID, secret string, err error) {
	parts := strings.Split(token, "_")
	if len(parts) != 4 || parts[0] != "sk" || parts[1] != "live" {
		return "", "", errors.New("invalid token format")
	}
	return parts[2], parts[3], nil
}

func hashSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}

func getProjectID() (string, error) {
	if metadata.OnGCE() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if id, err := metadata.ProjectIDWithContext(ctx); err == nil {
			return id, nil
		}
		return "", errors.New("failed to get project ID from GCE metadata service")
	}

	if id := os.Getenv("GCP_PROJECT_ID"); id != "" {
		return id, nil
	}
	return "", errors.New("GCP_PROJECT_ID environment variable is required for local development")
}

func initFirestore() error {
	ctx := context.Background()

	projectID, err := getProjectID()
	if err != nil {
		return fmt.Errorf("project ID resolution failed: %v", err)
	}

	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to create Firestore client: %v", err)
	}

	firestoreClient = client
	return nil
}

func validateBearerToken(token string) (*APIKey, error) {
	tenantID, secret, err := parseToken(token)
	if err != nil {
		return nil, err
	}

	if firestoreClient == nil {
		return nil, errors.New("firestore not configured")
	}

	ctx := context.Background()
	doc, err := firestoreClient.Collection("api_keys").Doc(tenantID).Get(ctx)
	if err != nil {
		return nil, errors.New("API key not found")
	}

	var apiKey APIKey
	if err := doc.DataTo(&apiKey); err != nil {
		return nil, errors.New("failed to parse API key data")
	}

	if !apiKey.IsActive {
		return nil, errors.New("API key is inactive")
	}

	expectedHash := hashSecret(secret)
	if expectedHash != apiKey.SecretHash {
		return nil, errors.New("invalid secret")
	}

	return &apiKey, nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"status": "ok",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func instagramFollowersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Method not allowed",
		})
		return
	}

	apiKey := r.Context().Value("tenant").(*APIKey)
	followerCount := getInstagramFollowers(apiKey.TenantID)

	response := map[string]int{
		"count": followerCount,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func getInstagramFollowers(tenantID string) int {
	mockData := map[string]int{
		"tenant123": 1234,
		"demo456":   5678,
	}
	if count, exists := mockData[tenantID]; exists {
		return count
	}
	return 0
}

func main() {
	if !metadata.OnGCE() {
		godotenv.Load()
	}

	if err := initFirestore(); err != nil {
		log.Fatalf("Firestore initialization failed: %v", err)
	}
	log.Println("Firestore client initialized")

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api/instagram/followers", bearerTokenMiddleware(instagramFollowersHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
