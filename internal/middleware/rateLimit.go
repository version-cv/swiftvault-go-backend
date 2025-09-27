package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"backend/internal/auth"
	"backend/internal/storage" 
)

// can be changed as needed 
var defaultRateLimit = 6

type RateLimitConfig struct {
	RequestsPerSecond int
}

// RateLimitMiddleware for public endpoints (IP-based)
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		key := fmt.Sprintf("rate_limit:ip:%s", clientIP)
		
		// The original hardcoded limit was 2 req/s in the error message, changing to defaultRateLimit
		if !allowRequest(key, defaultRateLimit) { 
			w.Header().Set("Retry-After", "1")
			http.Error(w, `{"success": false, "message": "Rate limit exceeded: Please try again in 1 second"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// UserRateLimitMiddleware for authenticated users per token per endpoint
func UserRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := getUserIdFromContext(r.Context())
		endpoint := r.URL.Path

		// Skip rate limiting for file uploads
		if endpoint == "/api/files/upload" {
			next.ServeHTTP(w, r)
			return
		}

		var key string
		if userID != "" {
			key = fmt.Sprintf("rate_limit:user:%s:endpoint:%s", userID, endpoint)
		} else {
			clientIP := getClientIP(r)
			key = fmt.Sprintf("rate_limit:ip:%s:endpoint:%s", clientIP, endpoint)
		}

		if !allowRequest(key, defaultRateLimit) { 
			w.Header().Set("Retry-After", "1")
			http.Error(w, `{"success": false, "message": "Rate limit exceeded: Please try again in 1 second"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}


func allowRequest(key string, limit int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond) 
	defer cancel()
	
	
	const ttlMilliseconds = 1000 


	currentCountStr, err := storage.PutKVWithTTL(ctx, key, 1000)
	if err != nil {
		// Log error, but allow request to proceed (Fail open)
		log.Printf("KV Rate Limiting Error (Fail Open): %v", err)
		return true
	}


	currentCount, _ := strconv.Atoi(currentCountStr) 

	newCount := currentCount + 1

	
	if newCount > limit {
		return false
	}


	err = storage.PutKVWithTTL(ctx, key, strconv.Itoa(newCount), ttlMilliseconds)
	if err != nil {
		log.Printf("KV Put Error during rate limiting: %v", err)
		return true 
	}

	return true
}


func getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	return strings.Split(r.RemoteAddr, ":")[0]
}

// Helper to extract user ID from context
func getUserIdFromContext(ctx context.Context) string {
	if claims, ok := ctx.Value("userClaims").(*auth.Claims); ok && claims != nil {
		return claims.UserID
	}
	return ""
}

// AdminRateLimitMiddleware with higher limits for admin users (optional)
func AdminRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims, ok := r.Context().Value("userClaims").(*auth.Claims); ok && claims != nil {
			key := fmt.Sprintf("rate_limit:user:%s", claims.UserID)
			
			adminLimit := 10
			if claims.Role == "admin" {
				if !allowRequest(key, adminLimit) {
					w.Header().Set("Retry-After", "1")
					http.Error(w, "Admin rate limit exceeded", http.StatusTooManyRequests)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
		}

		UserRateLimitMiddleware(next).ServeHTTP(w, r)
	})
}