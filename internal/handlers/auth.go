package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"errors"
	"net/http"
	"time"
	"log"
	"backend/internal/auth"
	"backend/internal/database"
	"backend/internal/storage"
	"backend/internal/models"
	"backend/internal/otp"
	"gorm.io/gorm"
	"backend/internal/emails"
)

type SendOTPRequest struct {
    Email string `json:"email"`
}
type SendResetOTPRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Email    string `json:"email"`
	NewPassword string `json:"newPassword"`
	OTP      string `json:"otp"`
}

type ErrorResponse struct {
    Success bool   `json:"success"`
    Message string `json:"message"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	OTP      string `json:"otp"`
}

type AuthResponse struct {
	Success      bool       `json:"success"`
	Token        string      `json:"token"`
	RefreshToken string      `json:"refreshToken"`
	User         models.User `json:"user"`
	ExpiresAt    time.Time   `json:"expiresAt"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type RefreshResponse struct {
	Success      bool       `json:"success"`
	Token     string    `json:"token"`
	RefreshToken     string    `json:"refreshToken"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type VerifyTokenRequest struct {
	Token string `json:"token"`
}

type VerifyTokenResponse struct {
	Success      bool       `json:"success"`
	Valid  bool           `json:"valid"`
	Claims *auth.Claims   `json:"claims,omitempty"`
	Error  string         `json:"error,omitempty"`
}



func sendJSONResponse(w http.ResponseWriter, status int, payload interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    if err := json.NewEncoder(w).Encode(payload); err != nil {
        log.Printf("Failed to encode response: %v", err)
    }
}

// LoginHandler handles user login requests
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse := ErrorResponse{
            Success: false,
            Message: "login successful",
        }
        sendJSONResponse(w, http.StatusBadRequest, errorResponse)
	}

	var user models.User
	result := database.DB.Where("email = ?", req.Email).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	if !auth.CheckPasswordHash(req.Password, user.Password) {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Generate access token
token, err := auth.GenerateToken(user.ID, user.Role)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Generate refresh token
	refreshToken, err := auth.GenerateRefreshToken(user.ID)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Calculate expiration time
	expirationTime := time.Now().Add(auth.AccessTokenExpiry)

	response := AuthResponse{
		Success:     true,
		Token:        token,
		RefreshToken: refreshToken,
		User:         user,
		ExpiresAt:    expirationTime,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func SendResetOTPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req SendResetOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid request payload"})
		return
	}

	var existingUser models.User
	// Correctly check if the user is NOT found. If err is not nil, it means the user doesn't exist.
	if err := database.DB.Where("email = ?", req.Email).First(&existingUser).Error; err != nil {
		// Log the specific error for debugging
		if errors.Is(err, gorm.ErrRecordNotFound) {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "User with this email is not registered"})
		} else {
			// Handle other database errors
			log.Printf("Database error checking for user: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to check user registration"})
		}
		return
	}

	otpCode := otp.GenerateOTP()
    key := fmt.Sprintf("otp:resetPwd:%s", req.Email)
	 ttlMs := int(otp.OTP_EXPIRATION.Milliseconds())
	 if err := storage.PutKVWithTTL(context.Background(), key, otpCode, ttlMs); err != nil {
        log.Printf("Error setting OTP via KV Worker: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to generate OTP"})
        return
    }

	go func() {
		if err := emails.SendResetEmail(req.Email, otpCode); err != nil {
			log.Printf("Error sending OTP email to %s: %v", req.Email, err)
		}
	}()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OTP sent to your email. Check your inbox."})
}

func SendOTPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req SendOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid request payload"})
		return
	}

	var existingUser models.User
	if err := database.DB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Email is already registered"})
		return
	}

	  otpCode := otp.GenerateOTP()
    key := fmt.Sprintf("otp:register:%s", req.Email)
	ttlMs := int(otp.OTP_EXPIRATION.Milliseconds())
	 if err := storage.PutKVWithTTL(context.Background(), key, otpCode, ttlMs); err != nil {
        log.Printf("Error setting OTP via KV Worker: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to generate OTP"})
        return
    }
    
	//Direct Async Call
    go func() {
        if err := emails.SendVerificationEmail(req.Email, otpCode); err != nil {
            log.Printf("Error sending OTP email to %s: %v", req.Email, err)
        }
    }()
   

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OTP sent to your email. Check your inbox."})
}

// RegisterHandler handles user registration requests
func ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    var req ResetPasswordRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid request payload"})
        return
    }

    // --- OTP VERIFICATION ---
   otpKey := fmt.Sprintf("otp:resetPwd:%s", req.Email)
  storedOTP, err := storage.GetKV(context.Background(), otpKey)
    if err != nil || storedOTP != req.OTP {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid or expired OTP"})
        return
    }

    // After successful OTP verification, retrieve the user from the database
    var user models.User
    if err := database.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "User not found"})
        return
    }

    // Hash the new password
    hashedPassword, err := auth.HashPassword(req.NewPassword)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to hash password"})
        return
    }

    // Update the user's password in the database
    if err := database.DB.Model(&user).Update("password", hashedPassword).Error; err != nil {
        log.Printf("Failed to update password for user %s: %v", user.Email, err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to reset password"})
        return
    }
    
    // Invalidate the OTP to prevent reuse
   if err := storage.DeleteKV(context.Background(), otpKey); err != nil {
    log.Printf("Warning: Failed to delete KV key %s: %v", otpKey, err)
}

    // Send a non-blocking email to confirm the password reset
    go func() {
        if err := emails.SendResetSuccessfulEmail(user.Email); err != nil {
            log.Printf("Failed to send password reset successful email to %s: %v", user.Email, err)
        }
    }()

    // Return a simple success message
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Password reset successful"})
}

// RegisterHandler handles user registration requests
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    var req RegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid request payload"})
        return
    }

    //  OTP VERIFICATION ---
  otpKey := fmt.Sprintf("otp:register:%s", req.Email)
   storedOTP, err := storage.GetKV(context.Background(), otpKey)

    if err != nil || storedOTP != req.OTP {
        w.WriteHeader(http.StatusUnauthorized)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid or expired OTP"})
        return
    }


  if err := storage.DeleteKV(context.Background(), otpKey); err != nil {
    log.Printf("Warning: Failed to delete expired OTP key %s via KV Worker: %v", otpKey, err)
}
    //  END OTP VERIFICATION ---

    // Check if email already exists
    var existingUser models.User
    result := database.DB.Where("email = ?", req.Email).First(&existingUser)
    if result.Error == nil {
        w.WriteHeader(http.StatusConflict)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Email already registered"})
        return
    } else if result.Error != gorm.ErrRecordNotFound {
        log.Printf("Database error checking for existing user: %v", result.Error)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Database error"})
        return
    }

    hashedPassword, err := auth.HashPassword(req.Password)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to hash password"})
        return
    }

    user := models.User{
        Email:    req.Email,
        Password: hashedPassword,
        Role:     "user",
        Plan:     "free",
    }

    if err := database.DB.Create(&user).Error; err != nil {
        log.Printf("Failed to create user: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to create user"})
        return
    }


		// go routine async send email nonblocking way
go func() {
    if err := emails.SendWelcomeEmail(user.Email); err != nil {
        log.Printf("Failed to send welcome email to %s: %v", user.Email, err)
    }
}()


    token, err := auth.GenerateToken(user.ID, user.Role)
    if err != nil {
        log.Printf("Failed to generate token: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to generate token"})
        return
    }

    refreshToken, err := auth.GenerateRefreshToken(user.ID)
    if err != nil {
        log.Printf("Failed to generate refresh token: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to generate refresh token"})
        return
    }

    expirationTime := time.Now().Add(auth.AccessTokenExpiry)
    response := AuthResponse{
        Success:      true,
        Token:        token,
        RefreshToken: refreshToken,
        User:         user,
        ExpiresAt:    expirationTime,
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(response)
}


// RefreshHandler handles token refresh requests
func RefreshHandler(w http.ResponseWriter, r *http.Request) {
    var req RefreshRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    // Validate refresh token
    claims, err := auth.ValidateRefreshToken(req.RefreshToken)
    if err != nil {
        http.Error(w, "Invalid refresh token: "+err.Error(), http.StatusUnauthorized)
        return
    }

    // Get user from database using the UUID string directly
    var user models.User
    result := database.DB.Where("id = ?", claims.UserID).First(&user)
    if result.Error != nil {
        if result.Error == gorm.ErrRecordNotFound {
            http.Error(w, "User not found", http.StatusUnauthorized)
        } else {
            http.Error(w, "Database error: "+result.Error.Error(), http.StatusInternalServerError)
        }
        return
    }

  
    token, err := auth.GenerateToken(user.ID, user.Role) 
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }
	
	refreshToken, err := auth.GenerateRefreshToken(user.ID)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

    // Calculate new expiration time
    expirationTime := time.Now().Add(auth.AccessTokenExpiry)

    response := RefreshResponse{
		Success:    true,
        Token:     token,
		RefreshToken: refreshToken,
        ExpiresAt: expirationTime,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// VerifyTokenHandler handles token verification requests
func VerifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate the token
	claims, err := auth.ValidateToken(req.Token)
	if err != nil {
		response := VerifyTokenResponse{
			Valid: false,
			Error: "Invalid token: " + err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Token is valid, return claims
	response := VerifyTokenResponse{
		Success:true,
		Valid:  true,
		Claims: claims,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// AuthMiddleware validates JWT tokens for protected routes
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "userClaims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetClaimsFromContext(ctx context.Context) (*auth.Claims, error) {
	claims, ok := ctx.Value("userClaims").(*auth.Claims)
	if !ok {
		return nil, fmt.Errorf("claims not found in context")
	}
	return claims, nil
}