package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"backend/internal/auth"
	"backend/internal/database"
	"backend/internal/graphql"
	"backend/internal/handlers"
	"backend/internal/middleware"
	"backend/internal/storage"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"backend/internal/redis" 
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Initialize database
	database.InitDB()

	// Initialize JWT
	if err := auth.InitJWT(); err != nil {
		log.Fatal("Failed to initialize JWT:", err)
	}

	// Initialize the minio object storage
	if err := storage.InitMinio(); err != nil {
		log.Fatal("Failed to initialize MinIO:", err)
	}

// Initialize the single global Redis client
	redis.InitRedis()

	graphqlSchema := graphql.InitSchema()

	// Create router
	router := mux.NewRouter()
	router.Handle("/graphql", 
    handlers.AuthMiddleware(
        middleware.UserRateLimitMiddleware(
            graphql.GraphQLHandler(graphqlSchema), 
        ),
    ),
).Methods("POST", "OPTIONS")

	// Public routes with IP-based limiting (no auth)
	
	router.Handle("/api/public/send-otp",
        middleware.RateLimitMiddleware(http.HandlerFunc(handlers.SendOTPHandler))).Methods("POST")
		router.Handle("/api/public/send-reset-otp",
        middleware.RateLimitMiddleware(http.HandlerFunc(handlers.SendResetOTPHandler))).Methods("POST")

	router.Handle("/api/register",
		middleware.RateLimitMiddleware(http.HandlerFunc(handlers.RegisterHandler))).Methods("POST")
		router.Handle("/api/reset-password",
		middleware.RateLimitMiddleware(http.HandlerFunc(handlers.ForgotPasswordHandler))).Methods("POST")

	router.Handle("/api/login",
		middleware.RateLimitMiddleware(http.HandlerFunc(handlers.LoginHandler))).Methods("POST")
		
	router.Handle("/api/refresh",
			middleware.RateLimitMiddleware(http.HandlerFunc(handlers.RefreshHandler))).Methods("POST")

    router.Handle("/api/public/file/{id}",
    middleware.RateLimitMiddleware(http.HandlerFunc(handlers.PublicFileHandler))).Methods("GET")
    
router.Handle("/api/public/folder/{id}",
    middleware.RateLimitMiddleware(http.HandlerFunc(handlers.PublicFolderHandler))).Methods("GET")	

router.Handle("/api/public/{id}/download",
    middleware.RateLimitMiddleware(http.HandlerFunc(handlers.PublicDownloadHandler))).Methods("GET")

	
		router.Handle("/api/file/{id}/download",
    middleware.UserRateLimitMiddleware(http.HandlerFunc(handlers.DownloadFileHandler)),
).Methods("GET")


	// Protected routes with auth rate limiter

	router.Handle("/api/verify-token",
		handlers.AuthMiddleware(
			middleware.UserRateLimitMiddleware(http.HandlerFunc(handlers.VerifyTokenHandler)),
		)).Methods("POST")

	router.Handle("/api/files/upload",
		handlers.AuthMiddleware(
			middleware.UserRateLimitMiddleware(http.HandlerFunc(handlers.FileUploadHandler)),
		)).Methods("POST")

	router.Handle("/api/files",
		handlers.AuthMiddleware(
			middleware.UserRateLimitMiddleware(http.HandlerFunc(handlers.GetUserFilesHandler)),
		)).Methods("GET")


	router.Handle("/api/files/{id}/download",
		handlers.AuthMiddleware(
			middleware.UserRateLimitMiddleware(http.HandlerFunc(handlers.DownloadFileHandler)),
		)).Methods("GET")

	router.Handle("/api/files/{id}",
		handlers.AuthMiddleware(
			middleware.UserRateLimitMiddleware(http.HandlerFunc(handlers.DeleteFileHandler)),
		)).Methods("DELETE")

	// Protected routes example
	router.Handle("/api/protected",
		handlers.AuthMiddleware(
			middleware.UserRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				claims, err := handlers.GetClaimsFromContext(r.Context())
				if err != nil {
					http.Error(w, "Failed to get user claims", http.StatusInternalServerError)
					return
				}

				response := map[string]interface{}{
					"message": "This is a protected endpoint",
					"userId":  claims.UserID,
					"role":    claims.Role,
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			})),
		)).Methods("GET")

	// Health check (no rate limiting)
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}