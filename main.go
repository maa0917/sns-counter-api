package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
)

type APIKey struct {
	TenantID   string
	Name       string
	IgUserID   string
	SecretHash string
	IsActive   bool
}

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

func validateBearerToken(token string) (*APIKey, error) {
	tenantID, secret, err := parseToken(token)
	if err != nil {
		return nil, err
	}

	// モックapi_keysコレクション構造
	mockAPIKeys := map[string]APIKey{
		"tenant123": {
			TenantID:   "tenant123",
			Name:       "Test Corp",
			IgUserID:   "12345",
			SecretHash: hashSecret("a1b2c3d4e5f6g7h8"),
			IsActive:   true,
		},
		"demo456": {
			TenantID:   "demo456",
			Name:       "Demo Company",
			IgUserID:   "67890",
			SecretHash: hashSecret("x9y8z7w6v5u4t3s2"),
			IsActive:   true,
		},
	}

	// 1. api_keysコレクションからドキュメント取得（Firestore風）
	apiKey, exists := mockAPIKeys[tenantID]
	if !exists || !apiKey.IsActive {
		return nil, errors.New("API key not found or inactive")
	}

	// 2. シークレットハッシュ検証
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
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api/instagram/followers", bearerTokenMiddleware(instagramFollowersHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
