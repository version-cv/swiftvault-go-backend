package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"mime"
    "path/filepath"  
    "strings"      
	"fmt"
	"io"
	"log"
	"time"
	"net/http"
	"backend/internal/auth"
	"backend/internal/database"
	"backend/internal/models"
	"backend/internal/storage"
	"github.com/gorilla/mux"
	"gorm.io/gorm"	
)

// Standard API response struct for consistency
type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// UploadResponse data for successful file uploads
type UploadResponseData struct {
    ID            string `json:"id"`
    OriginalName  string `json:"original_name"`
    FileSize      int64  `json:"file_size"`
    MimeType      string `json:"mime_type"`
    SHA256Hash    string `json:"sha256_hash"`
    IsPublic      bool   `json:"is_public"`
    DownloadCount int    `json:"download_count"`
    Tags          []string `json:"tags"`
    CreatedAt     string `json:"created_at"`
    UpdatedAt     string `json:"updated_at"`
}

func checkStorageQuota(userID string, newFileSize int64) error {
	var totalUsed int64
	result := database.DB.Model(&models.File{}).
		Select("COALESCE(SUM(fc.file_size), 0)").
		Joins("JOIN file_contents fc ON fc.id = files.file_content_id").
		Where("files.user_id = ?", userID).
		Scan(&totalUsed)

	if result.Error != nil {
		return result.Error
	}

	// 10MB default quota (from requirements)
	quota := int64(10 * 1024 * 1024)

	if totalUsed+newFileSize > quota {
		return fmt.Errorf("storage quota exceeded. Used: %d/%d bytes", totalUsed, quota)
	}

	return nil
}


var allowedMIMETypes = map[string]bool{
	"application/zip":                                      true,
	"application/x-zip-compressed":                         true,
	"audio/mpeg":                                           true,
	"audio/wav":                                            true,
       "audio/mp3":                    true,
    "audio/x-mpeg":                 true,
	"text/html":                                            true,
	"text/plain":                                           true,
	"image/jpeg":                                           true,
	"image/png":                                            true,
	"application/pdf":                                      true,
	"application/msword":                                   true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
	"application/vnd.ms-excel":                             true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":       true,
	"application/vnd.ms-powerpoint":                        true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
	"application/json":                                     true,
	"application/xml":                                      true,
	"application/javascript":                               true,
	"text/javascript":                                      true,
	"text/csv":                                             true,
	"video/mp4":                                            true,
	"image/gif":                                            true,
	"image/svg+xml":                                        true,
	"image/webp":                                           true,
	"application/x-tar":                                    true,
	"application/gzip":                                     true,
}


func validateMIMEType(fileBytes []byte, filename string) error {
	// Detect actual MIME type from content
	actualMIME := http.DetectContentType(fileBytes)
	fmt.Println("Detected MIME type:", actualMIME)
	actualMIME = strings.Split(actualMIME, ";")[0] 


	// Get expected MIME from file extension
	expectedMIME := mime.TypeByExtension(filepath.Ext(strings.ToLower(filename)))
	if expectedMIME == "" {
		return fmt.Errorf("unknown file extension: %s", filepath.Ext(filename))
	}
	expectedMIME = strings.Split(expectedMIME, ";")[0]

	// Check if the expected MIME type is in our allowed list
	if !allowedMIMETypes[expectedMIME] {
		return fmt.Errorf("file extension indicates an unsupported type: %s", expectedMIME)
	}

	//  check if detected type is within the same family
	if !strings.HasPrefix(actualMIME, strings.Split(expectedMIME, "/")[0]+"/") {
		return fmt.Errorf("file content (%s) does not match extension type family (%s)", actualMIME, expectedMIME)
	}
	
	return nil
}
func FileUploadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := GetClaimsFromContext(r.Context())
	if err != nil {
		log.Printf("Auth error: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Unauthorized"})
		return
	}

	err = r.ParseMultipartForm(32 << 20)
	if err != nil {
		log.Printf("Parse form error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to parse form: " + err.Error()})
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		log.Printf("Form file error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "No file uploaded: " + err.Error()})
		return
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		log.Printf("Read file error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to read file: " + err.Error()})
		return
	}

	//MimeType verification
	if err := validateMIMEType(fileBytes, fileHeader.Filename); err != nil {
    log.Printf("MIME validation failed: %v", err)
    w.WriteHeader(http.StatusBadRequest)
    json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid file type: " + err.Error()})
    return
}

	sha256Hash := auth.CalculateSHA256(fileBytes)
	log.Printf("File upload: user=%s, filename=%s, size=%d, hash=%s", claims.UserID, fileHeader.Filename, fileHeader.Size, sha256Hash)

	// Check for duplicate file content in the new file_contents table
	var existingContent models.FileContent
	result := database.DB.Where("sha256_hash = ?", sha256Hash).First(&existingContent)

	if result.Error == nil {
		// CASE 1: DEDUPLICATED FILE (Content already exists)
		log.Printf("File already exists, creating user reference: %s", existingContent.ID)

		err := checkStorageQuota(claims.UserID, existingContent.FileSize)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
			return
		}

		newFile := models.File{
			UserID:        claims.UserID,
			OriginalName:  fileHeader.Filename,
			FileContentID: existingContent.ID,
			IsPublic:      r.FormValue("isPublic") == "true",
		}

		if err := database.DB.Create(&newFile).Error; err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to save file metadata: " + err.Error()})
			return
		}

		response := UploadResponseData{
			ID:           newFile.ID,
			OriginalName: newFile.OriginalName,
			FileSize:     existingContent.FileSize,
			MimeType:     existingContent.MimeType,
			SHA256Hash:   existingContent.SHA256Hash,
			IsPublic:     newFile.IsPublic,
			 CreatedAt: newFile.CreatedAt.Format(time.RFC3339),
        UpdatedAt: newFile.UpdatedAt.Format(time.RFC3339),
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "File already exists (deduplicated)", Data: response})
		return

	} else if result.Error != gorm.ErrRecordNotFound {
		log.Printf("Deduplication check error: %v", result.Error)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Database error"})
		return
	}

	// CASE 2: NEW FILE (Content does not exist)
	log.Println("New file, proceeding with upload.")
	err = checkStorageQuota(claims.UserID, fileHeader.Size)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	newContent := models.FileContent{
		SHA256Hash:  sha256Hash,
		FileSize:    fileHeader.Size,
		MimeType:    fileHeader.Header.Get("Content-Type"),
		StorageName: fmt.Sprintf("%s_%s", sha256Hash, fileHeader.Filename),
	}
	if err := database.DB.Create(&newContent).Error; err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to save file content metadata"})
		return
	}

ctx := context.Background()
reader := bytes.NewReader(fileBytes) 

if err := storage.PutFile(
    ctx, 
    newContent.StorageName, 
    reader, 
    newContent.FileSize, 
    newContent.MimeType,
); err != nil {
    log.Printf("Failed to save file to R2 via Worker, rolling back database record: %v", err)
    database.DB.Delete(&newContent) // Crucial Rollback Logic
    w.WriteHeader(http.StatusInternalServerError)
    json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to save file to storage"})
    return
}

 newFile := models.File{
        UserID:          claims.UserID,
        OriginalName:    fileHeader.Filename,
        FileContentID:   newContent.ID,
        IsPublic:        r.FormValue("isPublic") == "true",
    }
    
    // Attempt to save the metadata record
    if err := database.DB.Create(&newFile).Error; err != nil {
        if deleteErr := storage.DeleteFile(context.Background(), newContent.StorageName); deleteErr != nil {
            log.Printf("Warning: Failed to delete uploaded R2 file during metadata rollback: %v", deleteErr)
        }
        database.DB.Delete(&newContent)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to save file metadata"})
        return
    }

	log.Printf("File saved successfully: %s", newFile.ID)

	response := UploadResponseData{
		ID:           newFile.ID,
		OriginalName: newFile.OriginalName,
		FileSize:     newContent.FileSize,
		MimeType:     newContent.MimeType,
		SHA256Hash:   newContent.SHA256Hash,
		IsPublic:     newFile.IsPublic,
		DownloadCount: newFile.DownloadCount,
        Tags: newFile.Tags,
        CreatedAt: newFile.CreatedAt.Format(time.RFC3339),
        UpdatedAt: newFile.UpdatedAt.Format(time.RFC3339),
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "File uploaded successfully", Data: response})
}

func GetUserFilesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := GetClaimsFromContext(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Unauthorized"})
		return
	}

	var files []models.File
	result := database.DB.
		Preload("FileContent").
		Where("files.user_id = ?", claims.UserID).
		Find(&files)
	if result.Error != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to fetch files"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Files fetched successfully", Data: files})
}

func DownloadFileHandler(w http.ResponseWriter, r *http.Request) {

    vars := mux.Vars(r)
    fileID := vars["id"]

    var file models.File
    result := database.DB.
        Preload("FileContent").
        Where("files.id = ?", fileID).
        First(&file)
    if result.Error != nil {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "File not found"})
        return
    }

    // Check for user authentication
    claims, err := GetClaimsFromContext(r.Context())
    if err != nil {
        // If there's no auth token, check if the file is public.
        if !file.IsPublic {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusUnauthorized)
            json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Unauthorized: File is private."})
            return
        }
    } else {
        // If an auth token exists, check user ownership or shared access.
        if file.UserID != claims.UserID && !file.IsPublic {
            var share models.FileShare
            shareResult := database.DB.Where("file_id = ? AND shared_with = ?", fileID, claims.UserID).First(&share)
            if shareResult.Error != nil {
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusForbidden)
                json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Access denied."})
                return
            }
        }
    }

   
    ctx := context.Background()
  object, err := storage.GetFile(ctx,  file.FileContent.StorageName)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to retrieve file"})
        return
    }
    defer object.Close()

    database.DB.Model(&file).Update("download_count", file.DownloadCount+1)

    w.Header().Set("Content-Type", file.FileContent.MimeType)
    w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", file.OriginalName))
    w.WriteHeader(http.StatusOK)
    io.Copy(w, object)
}



func DeleteFileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims, err := GetClaimsFromContext(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Unauthorized"})
		return
	}

	vars := mux.Vars(r)
	fileID := vars["id"]

	var file models.File
	result := database.DB.
		Preload("FileContent").
		Where("files.id = ? AND files.user_id = ?", fileID, claims.UserID).
		First(&file)
	if result.Error != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "File not found or access denied"})
		return
	}

	var referenceCount int64
	database.DB.Model(&models.File{}).
		Where("file_content_id = ? AND id != ?", file.FileContentID, file.ID).
		Count(&referenceCount)

	database.DB.Delete(&file)

	if referenceCount == 0 {
		ctx := context.Background()

	if err := storage.DeleteFile(ctx, file.FileContent.StorageName); err != nil {
    log.Printf("Warning: Failed to delete physical file from R2 via Worker: %v", err)
}
		database.DB.Delete(&file.FileContent)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "File deleted successfully", Data: map[string]string{"id": fileID}})
}

//public endpoint to fetch the public file details
func PublicFileHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    vars := mux.Vars(r)
    fileID := vars["id"]

    var file models.File
    result := database.DB.
        Preload("FileContent").
        Preload("User").
        Where("files.id = ? AND files.is_public = ?", fileID, true).
        First(&file)

    if result.Error != nil {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "File not found or not public."})
        return
    }


    responseData := map[string]interface{}{
        "id":            file.ID,
        "originalName":  file.OriginalName,
        "isPublic":      file.IsPublic,
        "downloadCount": file.DownloadCount + 1,
        "createdAt":     file.CreatedAt,
		"tags":             file.Tags,
        "mimeType":      file.FileContent.MimeType, 
		"size": file.FileContent.FileSize,
        "sharedBy": map[string]string{
            "id":    file.User.ID,
            "email": file.User.Email, 
        },
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(APIResponse{
        Success: true,
        Message: "File details fetched successfully.",
        Data:    responseData,
    })
}


// handler to fetch the pubic folder and related file details
func PublicFolderHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    vars := mux.Vars(r)
    folderID := vars["id"]

    var folder models.Folder
  
    result := database.DB.
        Preload("User").
        Preload("Files.User"). 
        Preload("Files.FileContent").
        Where("id = ? AND is_public = ?", folderID, true).
        First(&folder)

    if result.Error != nil {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Folder not found or not public."})
        return
    }

    filesData := make([]map[string]interface{}, len(folder.Files))
    for i, file := range folder.Files {
        filesData[i] = map[string]interface{}{
            "id":            file.ID,
            "originalName":  file.OriginalName,
            "fileSize":      file.FileContent.FileSize,
            "mimeType":      file.FileContent.MimeType,
            "downloadCount": file.DownloadCount,
            "isPublic":      file.IsPublic,
            "createdAt":     file.CreatedAt,
            "sharedBy": map[string]string{
                "email": file.User.Email,
            },
        }
    }

    responseData := map[string]interface{}{
        "id":        folder.ID,
        "name":      folder.Name,
        "isPublic":  folder.IsPublic,
        "createdAt": folder.CreatedAt,
        "sharedBy":  map[string]string{
            "email": folder.User.Email,
        },
        "files":     filesData,
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Folder fetched successfully", Data: responseData})
}


//public file download handler 
func PublicDownloadHandler(w http.ResponseWriter, r *http.Request) {

    vars := mux.Vars(r)
    fileID := vars["id"]

    var file models.File
    // Fetch the file, its content, and check if it's public.
    result := database.DB.
        Preload("FileContent").
        Where("files.id = ? AND files.is_public = ?", fileID, true).
        First(&file)

    if result.Error != nil {
        w.WriteHeader(http.StatusNotFound)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "File not found or not public."})
        return
    }

    // Increment the download count in a non-blocking goroutine.
    go func() {
        database.DB.Model(&file).UpdateColumn("download_count", gorm.Expr("download_count + ?", 1))
    }()

   
    ctx := context.Background()
   fileStream, err := storage.GetFile(ctx, file.FileContent.StorageName)
    if err != nil {
        log.Printf("Error getting public file from storage: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to retrieve public file from storage."})
        return
    }
    defer fileStream.Close()

    // Stream the file to the user.
    w.Header().Set("Content-Type", file.FileContent.MimeType)
    w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", file.OriginalName))
    w.WriteHeader(http.StatusOK)
    io.Copy(w, fileStream)
}