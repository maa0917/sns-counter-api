package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func apiKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("x-api-key")
		if apiKey == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "API key required",
			})
			return
		}

		if !isValidAPIKey(apiKey) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid API key",
			})
			return
		}

		ctx := context.WithValue(r.Context(), "api_key", apiKey)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func isValidAPIKey(apiKey string) bool {
	validKeys := []string{
		"test-key-123",
		"demo-key-456",
	}
	for _, key := range validKeys {
		if key == apiKey {
			return true
		}
	}
	return false
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

	apiKey := r.Context().Value("api_key").(string)
	followerCount := getInstagramFollowers(apiKey)

	response := map[string]int{
		"count": followerCount,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func getInstagramFollowers(apiKey string) int {
	mockData := map[string]int{
		"test-key-123": 1234,
		"demo-key-456": 5678,
	}
	if count, exists := mockData[apiKey]; exists {
		return count
	}
	return 0
}

func main() {
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api/instagram/followers", apiKeyMiddleware(instagramFollowersHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
