package handlers

import (
	"encoding/json"
	"net/http"

	"backend/internal/database"
	"backend/internal/models"
)

type ShareRequest struct {
	FileID      string `json:"fileId"`
	SharedWith string `json:"sharedWith"` 
	CanEdit bool `json:"canEdit"`
}

func ShareFileHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := GetClaimsFromContext(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req ShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if user owns the file
	var file models.File
	if err := database.DB.Where("id = ? AND user_id = ?", req.FileID, claims.UserID).First(&file).Error; err != nil {
		http.Error(w, "File not found or access denied", http.StatusNotFound)
		return
	}

	if req.SharedWith == "public" {
		// Make file public
		file.IsPublic = true
		if err := database.DB.Save(&file).Error; err != nil {
			http.Error(w, "Failed to share file", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"success":   true,
			"message":   "File made public successfully",
			"fileId":    file.ID,
			"publicUrl": "/api/public/download/?id="+file.ID,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Share with specific user
	var targetUser models.User
	if err := database.DB.Where("email = ?", req.SharedWith).First(&targetUser).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Create share record
	share := models.FileShare{
		FileID:      file.ID,
		SharedBy:    claims.UserID,
		SharedWith:  targetUser.ID,
		CanEdit:     req.CanEdit,
	}

	if err := database.DB.Create(&share).Error; err != nil {
		http.Error(w, "Failed to share file", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "File shared successfully",
		"shareId": share.ID,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetSharedFilesHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := GetClaimsFromContext(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get shared files with sharer information
	type SharedFileResponse struct {
		File    models.File `json:"file"`
		Sharer  models.User `json:"sharer"`
		CanEdit bool        `json:"canEdit"`
	}

	var shares []models.FileShare
	err = database.DB.
		Preload("File").
		Preload("File.FileContent").
		Preload("File.User").
		Joins("JOIN users ON users.id = file_shares.shared_by").
		Where("file_shares.shared_with = ?", claims.UserID).
		Find(&shares).Error

	if err != nil {
		http.Error(w, "Failed to fetch shared files", http.StatusInternalServerError)
		return
	}

	response := make([]SharedFileResponse, len(shares))
	for i, share := range shares {
		var sharer models.User
		database.DB.Where("id = ?", share.SharedBy).First(&sharer)
		
		response[i] = SharedFileResponse{
			File:    share.File,
			Sharer:  sharer,
			CanEdit: share.CanEdit,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}