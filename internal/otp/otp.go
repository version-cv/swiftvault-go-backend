package otp

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"backend/internal/storage" 
)

const OTP_EXPIRATION = 10 * time.Minute

// GenerateOTP creates a 6-digit random code
func GenerateOTP() string {
	// Note: rand.Seed is deprecated in Go 1.20+ and replaced by new methods, 
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%06d", rand.Intn(999999))
}


func SaveVerificationCode(userID, code string) error {
	key := fmt.Sprintf("otp:register:%s", userID)
	
	ttlMs := int(OTP_EXPIRATION.Milliseconds())


	return storage.PutKVWithTTL(context.Background(), key, code, ttlMs)
}

// VerifyOTP checks the code against KV.
func VerifyOTP(userID, code string) (bool, error) {
	key := fmt.Sprintf("otp:register:%s", userID)
	

	val, err := storage.GetKV(context.Background(), key)
	

	if err != nil {
	
		return false, fmt.Errorf("error retrieving OTP from KV: %w", err)
	}
	

	return val == code, nil
}
