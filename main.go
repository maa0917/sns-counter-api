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

type Tenant struct {
	Name          string `firestore:"name"`
	IgUserID      string `firestore:"ig_user_id"`
	IgAccessToken string `firestore:"ig_access_token"`
	SecretHash    string `firestore:"secret_hash"`
	IsActive      bool   `firestore:"is_active"`
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
		tenantID, _, err := parseToken(token)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid token",
			})
			return
		}

		tenant, err := validateBearerToken(token)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid token",
			})
			return
		}

		ctx := context.WithValue(r.Context(), "tenant", tenant)
		ctx = context.WithValue(ctx, "tenantID", tenantID)
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

func validateBearerToken(token string) (*Tenant, error) {
	tenantID, secret, err := parseToken(token)
	if err != nil {
		return nil, err
	}

	if firestoreClient == nil {
		return nil, errors.New("firestore not configured")
	}

	ctx := context.Background()
	doc, err := firestoreClient.Collection("tenants").Doc(tenantID).Get(ctx)
	if err != nil {
		return nil, errors.New("API key not found")
	}

	var tenant Tenant
	if err := doc.DataTo(&tenant); err != nil {
		return nil, errors.New("failed to parse API key data")
	}

	if !tenant.IsActive {
		return nil, errors.New("API key is inactive")
	}

	expectedHash := hashSecret(secret)
	if expectedHash != tenant.SecretHash {
		return nil, errors.New("invalid secret")
	}

	return &tenant, nil
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

	tenant := r.Context().Value("tenant").(*Tenant)
	tenantID := r.Context().Value("tenantID").(string)
	followerCount := getInstagramFollowers(tenantID, tenant)

	response := map[string]int{
		"count": followerCount,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func getInstagramFollowers(tenantID string, tenant *Tenant) int {
	if tenant.IgUserID == "" || tenant.IgAccessToken == "" {
		log.Printf("Missing Instagram credentials for tenant %s", tenantID)
		return 0
	}

	url := fmt.Sprintf("https://graph.facebook.com/v23.0/%s?fields=followers_count&access_token=%s",
		tenant.IgUserID, tenant.IgAccessToken)

	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Failed to call Instagram API for tenant %s: %v", tenantID, err)
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Instagram API returned status %d for tenant %s", resp.StatusCode, tenantID)
		return 0
	}

	var result struct {
		FollowersCount int `json:"followers_count"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Failed to decode Instagram API response for tenant %s: %v", tenantID, err)
		return 0
	}

	return result.FollowersCount
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
	http.HandleFunc("/api/v1/instagram/followers", bearerTokenMiddleware(instagramFollowersHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
