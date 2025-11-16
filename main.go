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

type Config struct {
	AllowedOrigins string
	Port           string
	GCPProjectID   string
}

type App struct {
	config    *Config
	firestore *firestore.Client
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func loadConfig() *Config {
	return &Config{
		AllowedOrigins: getEnv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173,http://localhost:8080"),
		Port:           getEnv("PORT", "8080"),
		GCPProjectID:   getEnv("GCP_PROJECT_ID", ""),
	}
}

func (app *App) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowedOrigins := app.config.AllowedOrigins

		origin := r.Header.Get("Origin")
		isAllowed := false

		if origin != "" {
			for _, allowedOrigin := range strings.Split(allowedOrigins, ",") {
				if strings.TrimSpace(allowedOrigin) == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					isAllowed = true
					break
				}
			}

			if !isAllowed {
				log.Printf("CORS: Origin '%s' not allowed", origin)
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func (app *App) bearerTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
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

		tenant, err := app.validateBearerToken(token)
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

func initFirestore(config *Config) (*firestore.Client, error) {
	ctx := context.Background()

	var projectID string
	if metadata.OnGCE() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if id, err := metadata.ProjectIDWithContext(ctx); err == nil {
			projectID = id
		} else {
			return nil, errors.New("failed to get project ID from GCE metadata service")
		}
	} else {
		if config.GCPProjectID != "" {
			projectID = config.GCPProjectID
		} else {
			return nil, errors.New("GCP_PROJECT_ID environment variable is required for local development")
		}
	}

	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to create Firestore client: %v", err)
	}

	return client, nil
}

func (app *App) validateBearerToken(token string) (*Tenant, error) {
	tenantID, secret, err := parseToken(token)
	if err != nil {
		return nil, err
	}

	if app.firestore == nil {
		return nil, errors.New("firestore not configured")
	}

	ctx := context.Background()
	doc, err := app.firestore.Collection("tenants").Doc(tenantID).Get(ctx)
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

// platformSettingsHandler handles platform settings GET/POST (STUB implementation)
func platformSettingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		response := map[string]string{
			"platform": "instagram",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)

	case http.MethodPost:
		var requestBody struct {
			Platform string `json:"platform"`
		}

		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid JSON body",
			})
			return
		}

		// STUB: Just return success without actually updating anything
		response := map[string]string{
			"message":  "Platform updated successfully",
			"platform": requestBody.Platform,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Method not allowed",
		})
	}
}

func main() {
	if !metadata.OnGCE() {
		godotenv.Load()
	}

	config := loadConfig()

	firestoreClient, err := initFirestore(config)
	if err != nil {
		log.Fatalf("Firestore initialization failed: %v", err)
	}
	log.Println("Firestore client initialized")

	app := &App{
		config:    config,
		firestore: firestoreClient,
	}

	http.HandleFunc("/health", app.corsMiddleware(healthHandler))
	http.HandleFunc("/api/v1/followers/count", app.corsMiddleware(app.bearerTokenMiddleware(instagramFollowersHandler)))
	http.HandleFunc("/api/v1/settings/platform", app.corsMiddleware(app.bearerTokenMiddleware(platformSettingsHandler)))

	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}
