package handlers

import (
 "encoding/json"
 "net/http"

"backend/internal/database"
 "backend/internal/models"
)

type CreateFolderRequest struct {
   Name    string `json:"name"`
    ParentID  string `json:"parentId"`
    IsPublic  bool   `json:"isPublic"`
}

func CreateFolderHandler(w http.ResponseWriter, r *http.Request) {
 claims, err := GetClaimsFromContext(r.Context())
 if err != nil {
 http.Error(w, "Unauthorized", http.StatusUnauthorized)
 return
 }

 var req CreateFolderRequest
if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
http.Error(w, "Invalid request body", http.StatusBadRequest)
 return
 }

 folder := models.Folder{
UserID:  claims.UserID,
 Name:  req.Name,
  IsPublic: req.IsPublic,
}

if req.ParentID != "" {
 folder.ParentID = &req.ParentID
 }

 if err := database.DB.Create(&folder).Error; err != nil {
 http.Error(w, "Failed to create folder", http.StatusInternalServerError)
 return
}

w.Header().Set("Content-Type", "application/json")
 json.NewEncoder(w).Encode(folder)
}

func AddFileToFolderHandler(w http.ResponseWriter, r *http.Request) {
claims, err := GetClaimsFromContext(r.Context())
 if err != nil {
 http.Error(w, "Unauthorized", http.StatusUnauthorized)
 return
 }

 var req struct {
FolderID string `json:"folderId"`
 FileID  string `json:"fileId"`
 }

 if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
http.Error(w, "Invalid request body", http.StatusBadRequest)
 return
}

  // Check if user owns both folder and file
    var folder models.Folder
    if err := database.DB.Where("id = ? AND user_id = ?", req.FolderID, claims.UserID).First(&folder).Error; err != nil {
     http.Error(w, "Folder not found or access denied", http.StatusNotFound)
       return
    }

    var file models.File
    if err := database.DB.Where("id = ? AND user_id = ?", req.FileID, claims.UserID).First(&file).Error; err != nil {
       http.Error(w, "File not found or access denied", http.StatusNotFound)
     return
 }

  folderItem := models.FolderItem{
        FolderID: req.FolderID,
        FileID:   req.FileID,
    }

    if err := database.DB.Create(&folderItem).Error; err != nil {
        http.Error(w, "Failed to add file to folder", http.StatusInternalServerError)
 return
 }

    response := map[string]interface{}{
        "success": true,
        "message": "File added to folder successfully",
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}