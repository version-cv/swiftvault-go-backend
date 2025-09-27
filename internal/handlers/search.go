package handlers

import (
	"encoding/json"
	"net/http"
	"time"
	"backend/internal/database"
	"backend/internal/models"
)

type SearchRequest struct {
	Query    string `json:"query"`
	MimeType string `json:"mimeType"`
	Tag      string `json:"tag"`
	SizeMin  int64  `json:"sizeMin"`
	SizeMax  int64  `json:"sizeMax"`
	DateFrom string `json:"dateFrom"`
	DateTo   string `json:"dateTo"`
	Uploader string `json:"uploader"`
}

func SearchFilesHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := GetClaimsFromContext(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Build query with joins
	query := database.DB.Model(&models.File{}).
		Preload("FileContent").
		Joins("JOIN users ON users.id = files.user_id").
		Where("files.user_id = ? OR files.is_public = true", claims.UserID)

	// Apply filters
	if req.Query != "" {
		query = query.Where("files.original_name ILIKE ?", "%"+req.Query+"%")
	}
	if req.MimeType != "" {
		query = query.Joins("JOIN file_contents fc ON fc.id = files.file_content_id").Where("fc.mime_type = ?", req.MimeType)
	}
	if req.Tag != "" {
		query = query.Where("? = ANY(files.tags)", req.Tag)
	}
	if req.SizeMin > 0 {
		query = query.Joins("JOIN file_contents fc ON fc.id = files.file_content_id").Where("fc.file_size >= ?", req.SizeMin)
	}
	if req.SizeMax > 0 {
		query = query.Joins("JOIN file_contents fc ON fc.id = files.file_content_id").Where("fc.file_size <= ?", req.SizeMax)
	}
	if req.DateFrom != "" {
		if dateFrom, err := time.Parse(time.RFC3339, req.DateFrom); err == nil {
			query = query.Where("files.created_at >= ?", dateFrom)
		}
	}
	if req.DateTo != "" {
		if dateTo, err := time.Parse(time.RFC3339, req.DateTo); err == nil {
			query = query.Where("files.created_at <= ?", dateTo)
		}
	}
	if req.Uploader != "" {
		query = query.Where("users.email ILIKE ?", "%"+req.Uploader+"%")
	}

	var files []models.File
	if err := query.Find(&files).Error; err != nil {
		http.Error(w, "Failed to search files", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}