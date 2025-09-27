package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"encoding/json" 
)

type KVPayload struct {
	Key: string `json:"key"`
	Value          string `json:"value"`
	ExpirationTtl int    `json:"expirationTtl"`
}


var WorkerClient *http.Client

// InitWorkerClient initializes the HTTP client for the Cloudflare Worker.
func InitWorkerClient() {
	WorkerClient = &http.Client{}
}

// ====================================================================
// R2 Functions (File Storage)
// ====================================================================

// PutFile sends a PUT request to the Cloudflare Worker to upload a file to R2.
func PutFile(ctx context.Context, objectName string, reader io.Reader, objectSize int64, contentType string) error {
	workerEndpoint := os.Getenv("WORKER_ENDPOINT")
	if workerEndpoint == "" {
		return fmt.Errorf("WORKER_ENDPOINT environment variable is required")
	}

	url := fmt.Sprintf("%s/r2/%s", workerEndpoint, objectName)

	req, err := http.NewRequestWithContext(ctx, "PUT", url, reader)
	if err != nil {
		return err
	}
	req.ContentLength = objectSize
	req.Header.Set("Content-Type", contentType)

	resp, err := WorkerClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to upload file: status code %d", resp.StatusCode)
	}

	return nil
}

func PutKVWithTTL(ctx context.Context, key string, value string, expirationTtl int) error {
	workerEndpoint := os.Getenv("WORKER_ENDPOINT")
	if workerEndpoint == "" {
		return fmt.Errorf("WORKER_ENDPOINT environment variable is required")
	}

	url := fmt.Sprintf("%s/kv/", workerEndpoint)

	payload := KVPayload{
		Key:    key,
		Value:          value,
		ExpirationTtl: expirationTtl,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal KV payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	// CRITICAL: Set content type to application/json
	req.Header.Set("Content-Type", "application/json") 

	resp, err := WorkerClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to set KV pair: status code %d", resp.StatusCode)
	}

	return nil
}

// GetKV sends a GET request to the Cloudflare Worker to retrieve a value from KV.
func GetKV(ctx context.Context, key string) (string, error) {
	workerEndpoint := os.Getenv("WORKER_ENDPOINT")
	if workerEndpoint == "" {
		return "", fmt.Errorf("WORKER_ENDPOINT environment variable is required")
	}

	url := fmt.Sprintf("%s/kv/%s", workerEndpoint, key)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := WorkerClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get KV value: status code %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(bodyBytes), nil
}


// DeleteKV sends a DELETE request to the Cloudflare Worker to remove a key from KV.
func DeleteKV(ctx context.Context, key string) error {
	workerEndpoint := os.Getenv("WORKER_ENDPOINT")
	if workerEndpoint == "" {
		return fmt.Errorf("WORKER_ENDPOINT environment variable is required")
	}

	url := fmt.Sprintf("%s/kv/%s", workerEndpoint, key)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}

	resp, err := WorkerClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 200 OK or 204 No Content typically means success
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete KV key: status code %d", resp.StatusCode)
	}

	return nil
}


//CLOUDFLARE R2 RELATED FUNCTIONS 

// GetFile sends a GET request to the Cloudflare Worker to retrieve a file from R2.
func GetFile(ctx context.Context, objectName string) (io.ReadCloser, error) {
	workerEndpoint := os.Getenv("WORKER_ENDPOINT")
	if workerEndpoint == "" {
		return nil, fmt.Errorf("WORKER_ENDPOINT environment variable is required")
	}

	url := fmt.Sprintf("%s/r2/%s", workerEndpoint, objectName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := WorkerClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to get file: status code %d", resp.StatusCode)
	}

	return resp.Body, nil
}



func DeleteFile(ctx context.Context, objectName string) error {
	workerEndpoint := os.Getenv("WORKER_ENDPOINT")
	if workerEndpoint == "" {
		return fmt.Errorf("WORKER_ENDPOINT environment variable is required")
	}

	url := fmt.Sprintf("%s/r2/%s", workerEndpoint, objectName)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}

	resp, err := WorkerClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete file: status code %d", resp.StatusCode)
	}

	return nil
}