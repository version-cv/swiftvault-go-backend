package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

// Token expiration constants
const (
	AccessTokenExpiry  = 1 * time.Hour     // 1 hour for access tokens
	RefreshTokenExpiry = 7 * 24 * time.Hour // 7 days for refresh tokens
)

func InitJWT() error {
	// Try to load keys from environment variables first
	privKeyPEM := os.Getenv("JWT_PRIVATE_KEY")
	pubKeyPEM := os.Getenv("JWT_PUBLIC_KEY")

	if privKeyPEM != "" && pubKeyPEM != "" {
		// Load keys from environment variables
		privKey, err := parsePrivateKey(privKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}

		pubKey, err := parsePublicKey(pubKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %v", err)
		}

		privateKey = privKey
		publicKey = pubKey
		log.Println("JWT keys loaded from environment variables")
		return nil
	}

	// Try to load keys from files
	privKeyFile := os.Getenv("JWT_PRIVATE_KEY_FILE")
	pubKeyFile := os.Getenv("JWT_PUBLIC_KEY_FILE")

	if privKeyFile != "" && pubKeyFile != "" {
		privKey, err := loadPrivateKeyFromFile(privKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load private key from file: %v", err)
		}

		pubKey, err := loadPublicKeyFromFile(pubKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load public key from file: %v", err)
		}

		privateKey = privKey
		publicKey = pubKey
		log.Println("JWT keys loaded from files")
		return nil
	}

	// Fallback: generate new keys (for development only)
	log.Println("WARNING: No JWT keys found in environment. Generating new keys (not recommended for production)")
	privateKey, publicKey = generateRSAKeys()
	return nil
}

func generateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return privateKey, &privateKey.PublicKey
}

func parsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	// Handle both with and without PEM headers
	if !strings.Contains(pemData, "-----BEGIN") {
		pemData = "-----BEGIN RSA PRIVATE KEY-----\n" + pemData + "\n-----END RSA PRIVATE KEY-----"
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing private key")
	}

	if block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected key type: %s", block.Type)
	}

	// Try PKCS1 first
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	// Try PKCS8
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	return privateKey, nil
}

func parsePublicKey(pemData string) (*rsa.PublicKey, error) {
	// Handle both with and without PEM headers
	if !strings.Contains(pemData, "-----BEGIN") {
		pemData = "-----BEGIN PUBLIC KEY-----\n" + pemData + "\n-----END PUBLIC KEY-----"
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing public key")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected key type: %s", block.Type)
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return publicKey, nil
}

func loadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parsePrivateKey(string(data))
}

func loadPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(string(data))
}

// Claims for access tokens
type Claims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// RefreshClaims for refresh tokens
type RefreshClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func GenerateToken(userID, role string) (string, error) {
	expirationTime := time.Now().Add(AccessTokenExpiry)

	claims := &Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "backend",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// GenerateRefreshToken creates a refresh token
func GenerateRefreshToken(userID string) (string, error) {
	expirationTime := time.Now().Add(RefreshTokenExpiry)

	claims := &RefreshClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "backend",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// ValidateRefreshToken validates refresh tokens
func ValidateRefreshToken(tokenString string) (*RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*RefreshClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid refresh token")
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ExportPublicKeyPEM exports the public key as PEM string
func ExportPublicKeyPEM() (string, error) {
	if publicKey == nil {
		return "", errors.New("public key not initialized")
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return string(pubPEM), nil
}