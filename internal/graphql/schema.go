package graphql

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
"github.com/lib/pq"
	"backend/internal/storage"
	"backend/internal/auth"
	"backend/internal/database"
	"backend/internal/models"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"gorm.io/gorm"
)

// Define auth context key
type authContextKey struct{}

// Custom scalar for DateTime
var DateTime = graphql.NewScalar(graphql.ScalarConfig{
	Name: "DateTime",
	Description: "DateTime scalar type",
	Serialize: func(value interface{}) interface{} {
		if t, ok := value.(time.Time); ok {
			return t.Format(time.RFC3339)
		}
		return nil
	},
	ParseValue: func(value interface{}) interface{} {
		if str, ok := value.(string); ok {
			if t, err := time.Parse(time.RFC3339, str); err == nil {
				return t
			}
		}
		return nil
	},
	ParseLiteral: func(valueAST ast.Value) interface{} {
		if str, ok := valueAST.(*ast.StringValue); ok {
			if t, err := time.Parse(time.RFC3339, str.Value); err == nil {
				return t
			}
		}
		return nil
	},
})

// --- Response wrapper types for success tracking ---

var operationResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "OperationResult",
	Fields: graphql.Fields{
		"success": &graphql.Field{Type: graphql.Boolean},
		"message": &graphql.Field{Type: graphql.String},
	},
})

var fileResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "FileResult",
	Fields: graphql.Fields{
		"success": &graphql.Field{Type: graphql.Boolean},
		"message": &graphql.Field{Type: graphql.String},
		"file": &graphql.Field{Type: fileType},
	},
})

var filesResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "FilesResult",
	Fields: graphql.Fields{
		"success": &graphql.Field{Type: graphql.Boolean},
		"message": &graphql.Field{Type: graphql.String},
		"files": &graphql.Field{Type: graphql.NewList(fileType)},
	},
})

var folderResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "FolderResult",
	Fields: graphql.Fields{
		"success": &graphql.Field{Type: graphql.Boolean},
		"message": &graphql.Field{Type: graphql.String},
		"folder": &graphql.Field{Type: folderType},
	},
})

var foldersResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "FoldersResult",
	Fields: graphql.Fields{
		"success": &graphql.Field{Type: graphql.Boolean},
		"message": &graphql.Field{Type: graphql.String},
		"folders": &graphql.Field{Type: graphql.NewList(folderType)},
	},
})

var fileSharesResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "FileSharesResult",
	Fields: graphql.Fields{
		"success": &graphql.Field{Type: graphql.Boolean},
		"message": &graphql.Field{Type: graphql.String},
		"shares": &graphql.Field{Type: graphql.NewList(fileShareType)},
	},
})

var folderSharesResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "FolderSharesResult",
	Fields: graphql.Fields{
		"success": &graphql.Field{Type: graphql.Boolean},
		"message": &graphql.Field{Type: graphql.String},
		"shares": &graphql.Field{Type: graphql.NewList(folderShareType)},
	},
})

var storageStatsResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "StorageStatsResult",
	Fields: graphql.Fields{
		"success": &graphql.Field{Type: graphql.Boolean},
		"message": &graphql.Field{Type: graphql.String},
		"stats": &graphql.Field{Type: storageStatsType},
	},
})

var usersResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "UsersResult",
	Fields: graphql.Fields{
		"success": &graphql.Field{Type: graphql.Boolean},
		"message": &graphql.Field{Type: graphql.String},
		"users": &graphql.Field{Type: graphql.NewList(userWithStatsType)},
	},
})

// --- GraphQL Types ---
// This new type will be used to show stats per user for the admin query
var userWithStatsType = graphql.NewObject(graphql.ObjectConfig{
	Name: "UserWithStats",
	Fields: graphql.Fields{
		"id": &graphql.Field{Type: graphql.String},
		"email": &graphql.Field{Type: graphql.String},
		"role": &graphql.Field{Type: graphql.String},
		"plan": &graphql.Field{Type: graphql.String},
		"stats": &graphql.Field{
			Type: storageStatsType,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				user := p.Source.(models.User)

				var totalUsed int64
				database.DB.Model(&models.FileContent{}).
					Joins("JOIN files ON files.file_content_id = file_contents.id").
					Where("files.user_id = ?", user.ID).
					Select("COALESCE(SUM(DISTINCT file_contents.file_size), 0)").
					Scan(&totalUsed)

				var originalSize int64
				database.DB.Model(&models.File{}).
					Joins("JOIN file_contents fc ON fc.id = files.file_content_id").
					Where("files.user_id = ?", user.ID).
					Select("COALESCE(SUM(fc.file_size), 0)").
					Scan(&originalSize)

				var fileCount, uniqueFileCount int64
				database.DB.Model(&models.File{}).
					Where("user_id = ?", user.ID).
					Count(&fileCount)

				database.DB.Model(&models.FileContent{}).
					Joins("JOIN files ON files.file_content_id = file_contents.id").
					Where("files.user_id = ?", user.ID).
					Distinct("file_contents.id").
					Count(&uniqueFileCount)

				saved := originalSize - totalUsed
				savedPercentage := 0.0
				if originalSize > 0 {
					savedPercentage = float64(saved) / float64(originalSize) * 100
				}

				stats := map[string]interface{}{
					"totalUsed": totalUsed,
					"originalSize": originalSize,
					"saved": saved,
					"savedPercentage": savedPercentage,
					"fileCount": fileCount,
					"uniqueFileCount": uniqueFileCount,
					"duplicateFileCount": fileCount - uniqueFileCount,
				}

				return stats, nil
			},
		},
	},
})

var userType = graphql.NewObject(graphql.ObjectConfig{
	Name: "User",
	Fields: graphql.Fields{
		"id": &graphql.Field{Type: graphql.String},
		"email": &graphql.Field{Type: graphql.String},
		"role": &graphql.Field{Type: graphql.String},
		"plan": &graphql.Field{Type: graphql.String},
	},
})

var fileType = graphql.NewObject(graphql.ObjectConfig{
	Name: "File",
	Fields: graphql.Fields{
		"id": &graphql.Field{Type: graphql.String},
		"originalName": &graphql.Field{Type: graphql.String},
		"storageName": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				file := p.Source.(*models.File)
				return file.FileContent.StorageName, nil
			},
		},
		"fileSize": &graphql.Field{
			Type: graphql.Int,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				file := p.Source.(*models.File)
				return file.FileContent.FileSize, nil
			},
		},
		"mimeType": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				file := p.Source.(*models.File)
				return file.FileContent.MimeType, nil
			},
		},
		"sha256Hash": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				file := p.Source.(*models.File)
				return file.FileContent.SHA256Hash, nil
			},
		},
		"isPublic": &graphql.Field{Type: graphql.Boolean},
		"downloadCount": &graphql.Field{Type: graphql.Int},
		"tags": &graphql.Field{Type: graphql.NewList(graphql.String)},
		"createdAt": &graphql.Field{Type: DateTime},
		"updatedAt": &graphql.Field{Type: DateTime},
		"user": &graphql.Field{
			Type: userType,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				file := p.Source.(*models.File)
				var user models.User
				if err := database.DB.Where("id = ?", file.UserID).First(&user).Error; err != nil {
					log.Printf("Error loading user %s: %v", file.UserID, err)
					return nil, nil
				}
				return user, nil
			},
		},
		"publicUrl": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				file := p.Source.(*models.File)
				if file.IsPublic {
					return fmt.Sprintf("/api/files/public/%s/download", file.ID), nil
				}
				return nil, nil
			},
		},
	},
})

var fileShareType = graphql.NewObject(graphql.ObjectConfig{
	Name: "FileShare",
	Fields: graphql.Fields{
		"id": &graphql.Field{Type: graphql.String},
		"fileId": &graphql.Field{Type: graphql.String},
		"sharedBy": &graphql.Field{Type: graphql.String},
		"sharedWith": &graphql.Field{Type: graphql.String},
		"canEdit": &graphql.Field{Type: graphql.Boolean},
		"createdAt": &graphql.Field{Type: DateTime},
		"file": &graphql.Field{
			Type: fileType,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				share := p.Source.(models.FileShare)
				var file models.File
				if err := database.DB.Preload("FileContent").First(&file, share.FileID).Error; err != nil {
					return nil, err
				}
				return &file, nil
			},
		},
		"sharer": &graphql.Field{
			Type: userType,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				share := p.Source.(models.FileShare)
				var user models.User
				if err := database.DB.Where("id = ?", share.SharedBy).First(&user).Error; err != nil {
					log.Printf("Error loading sharer %s: %v", share.SharedBy, err)
					return nil, nil
				}
				return user, nil
			},
		},
	},
})

var folderType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Folder",
	Fields: graphql.Fields{
		"id": &graphql.Field{Type: graphql.String},
		"name": &graphql.Field{Type: graphql.String},
		"isPublic": &graphql.Field{Type: graphql.Boolean},
		"parentId": &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: DateTime},
		"updatedAt": &graphql.Field{Type: DateTime},
		"user": &graphql.Field{
			Type: userType,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				folder := p.Source.(models.Folder)
				var user models.User
				if err := database.DB.Where("id = ?", folder.UserID).First(&user).Error; err != nil {
					log.Printf("Error loading user %s: %v", folder.UserID, err)
					return nil, nil
				}
				return user, nil
			},
		},
		"files": &graphql.Field{
			Type: graphql.NewList(fileType),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				folder := p.Source.(models.Folder)
				var files []models.File
				err := database.DB.
					Preload("FileContent").
					Joins("JOIN folder_items ON folder_items.file_id = files.id").
					Where("folder_items.folder_id = ?", folder.ID).
					Find(&files).Error

				filePointers := make([]*models.File, len(files))
				for i := range files {
					filePointers[i] = &files[i]
				}

				return filePointers, err
			},
		},
		"publicUrl": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				folder := p.Source.(models.Folder)
				if folder.IsPublic {
					return fmt.Sprintf("/api/folders/public/%s", folder.ID), nil
				}
				return nil, nil
			},
		},
	},
})

var folderShareType = graphql.NewObject(graphql.ObjectConfig{
	Name: "FolderShare",
	Fields: graphql.Fields{
		"id": &graphql.Field{Type: graphql.String},
		"folderId": &graphql.Field{Type: graphql.String},
		"folder": &graphql.Field{
			Type: folderType,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				share := p.Source.(models.FolderShare)
				var folder models.Folder
				if err := database.DB.First(&folder, share.FolderID).Error; err != nil {
					return nil, err
				}
				return folder, nil
			},
		},
		"sharedBy": &graphql.Field{Type: graphql.String},
		"sharer": &graphql.Field{
			Type: userType,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				share := p.Source.(models.FolderShare)
				var user models.User
				if err := database.DB.First(&user, share.SharedBy).Error; err != nil {
					log.Printf("Error loading sharer %s: %v", share.SharedBy, err)
					return nil, nil
				}
				return user, nil
			},
		},
		"sharedWith": &graphql.Field{Type: graphql.String},
		"canEdit": &graphql.Field{Type: graphql.Boolean},
		"createdAt": &graphql.Field{Type: DateTime},
	},
})

var storageStatsType = graphql.NewObject(graphql.ObjectConfig{
	Name: "StorageStats",
	Fields: graphql.Fields{
		"totalUsed": &graphql.Field{Type: graphql.Int},
		"originalSize": &graphql.Field{Type: graphql.Int},
		"saved": &graphql.Field{Type: graphql.Int},
		"savedPercentage": &graphql.Field{Type: graphql.Float},
		"fileCount": &graphql.Field{Type: graphql.Int},
		"uniqueFileCount": &graphql.Field{Type: graphql.Int},
		"duplicateFileCount": &graphql.Field{Type: graphql.Int},
	},
})

// --- GraphQL Resolver Logic ---

func InitSchema() *graphql.Schema {
	queryType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
		// Corrected files resolver in schema.go
"files": &graphql.Field{
    Type: filesResultType,
    Args: graphql.FieldConfigArgument{
        "query": &graphql.ArgumentConfig{Type: graphql.String},
        "mimeType": &graphql.ArgumentConfig{Type: graphql.String},
        "tag": &graphql.ArgumentConfig{Type: graphql.String},
        "sizeMin": &graphql.ArgumentConfig{Type: graphql.Int},
        "sizeMax": &graphql.ArgumentConfig{Type: graphql.Int},
        "dateFrom": &graphql.ArgumentConfig{Type: DateTime},
        "dateTo": &graphql.ArgumentConfig{Type: DateTime},
        "limit": &graphql.ArgumentConfig{Type: graphql.Int},
        "offset": &graphql.ArgumentConfig{Type: graphql.Int},
        "orderBy": &graphql.ArgumentConfig{
            Type: graphql.String,
            Description: "Field to order by (e.g., 'created_at')",
        },
        "order": &graphql.ArgumentConfig{
            Type: graphql.String,
            Description: "Ordering direction ('asc' or 'desc')",
        },
    },
    Resolve: func(p graphql.ResolveParams) (interface{}, error) {
    userID, ok := p.Context.Value(authContextKey{}).(string)
    if !ok {
        return map[string]interface{}{
            "success": false,
            "message": "Not authenticated",
            "files":   nil,
        }, nil
    }

    query := database.DB.Model(&models.File{}).
        Preload("FileContent").
        Where("files.user_id = ?", userID)

    // A flag to determine if we need to join the file_contents table.
    needsFileContentJoin := false

    // --- Determine if Join is Needed (check all relevant arguments first) ---
    if _, ok := p.Args["mimeType"].(string); ok {
        needsFileContentJoin = true
    }
    if _, ok := p.Args["sizeMin"].(int); ok {
        needsFileContentJoin = true
    }
    if _, ok := p.Args["sizeMax"].(int); ok {
        needsFileContentJoin = true
    }
    if orderBy, ok := p.Args["orderBy"].(string); ok && orderBy == "fileSize" {
        needsFileContentJoin = true
    }

    // --- The Fix: Perform the join only once here if needed ---
    if needsFileContentJoin {
        query = query.Joins("JOIN file_contents fc ON fc.id = files.file_content_id")
    }

    // --- Now apply the filters using the joined table ---
    if queryStr, ok := p.Args["query"].(string); ok && queryStr != "" {
        query = query.Where("files.original_name ILIKE ?", "%"+queryStr+"%")
    }
    if mimeTypeArg, ok := p.Args["mimeType"].(string); ok && mimeTypeArg != "" {
        if strings.Contains(mimeTypeArg, "/") {
            query = query.Where("fc.mime_type = ?", mimeTypeArg)
        } else {
            query = query.Where("fc.mime_type LIKE ?", mimeTypeArg+"/%")
        }
    }
    if tag, ok := p.Args["tag"].(string); ok && tag != "" {
        query = query.Where("? = ANY(files.tags)", tag)
    }
    if sizeMin, ok := p.Args["sizeMin"].(int); ok && sizeMin > 0 {
        query = query.Where("fc.file_size >= ?", sizeMin)
    }
    if sizeMax, ok := p.Args["sizeMax"].(int); ok && sizeMax > 0 {
        query = query.Where("fc.file_size <= ?", sizeMax)
    }
    if dateFrom, ok := p.Args["dateFrom"].(time.Time); ok {
        query = query.Where("files.created_at >= ?", dateFrom)
    }
    if dateTo, ok := p.Args["dateTo"].(time.Time); ok {
        query = query.Where("files.created_at <= ?", dateTo)
    }

    // --- Ordering Logic (which now correctly uses the joined table) ---
    orderBy, okOrderBy := p.Args["orderBy"].(string)
    if okOrderBy && orderBy != "" {
        dbColumn := ""
        switch orderBy {
        case "createdAt":
            dbColumn = "created_at"
        case "originalName":
            dbColumn = "original_name"
        case "fileSize":
            dbColumn = "file_size"
        default:
            dbColumn = "created_at"
        }

        direction := "asc"
        if order, ok := p.Args["order"].(string); ok && strings.ToLower(order) == "desc" {
            direction = "desc"
        }
        
        if dbColumn == "file_size" {
            query = query.Order(fmt.Sprintf("fc.%s %s", dbColumn, direction))
        } else {
            query = query.Order(fmt.Sprintf("files.%s %s", dbColumn, direction))
        }
    } else {
        query = query.Order("files.created_at desc")
    }

    if limit, ok := p.Args["limit"].(int); ok && limit > 0 {
        query = query.Limit(limit)
    }

    if offset, ok := p.Args["offset"].(int); ok && offset >= 0 {
        query = query.Offset(offset)
    }

    var files []models.File
    if err := query.Find(&files).Error; err != nil {
        return map[string]interface{}{
            "success": false,
            "message": fmt.Sprintf("Error fetching files: %v", err),
            "files":   nil,
        }, nil
    }

    filePointers := make([]*models.File, len(files))
    for i := range files {
        filePointers[i] = &files[i]
    }

    return map[string]interface{}{
        "success": true,
        "message": "Files fetched successfully",
        "files":   filePointers,
    }, nil
},
},

			"me": &graphql.Field{
                Type: userType,
                Description: "Fetches the currently authenticated user's profile.",
                Resolve: func(p graphql.ResolveParams) (interface{}, error) {
                    userID, ok := p.Context.Value(authContextKey{}).(string)
                    if !ok {
                        return nil, fmt.Errorf("not authenticated")
                    }
                    
                    var user models.User
                    if err := database.DB.Where("id = ?", userID).First(&user).Error; err != nil {
                        return nil, fmt.Errorf("user not found: %v", err)
                    }
                    
                    return user, nil
                },
            },

			"file": &graphql.Field{
				Type: fileResultType,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
							"file": nil,
						}, nil
					}

					fileID := p.Args["id"].(string)
					var file models.File
					err := database.DB.
						Preload("FileContent").
						Where("files.id = ? AND (files.user_id = ? OR files.is_public = true)", fileID, userID).
						First(&file).Error

					if err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error fetching file: %v", err),
							"file": nil,
						}, nil
					}

					return map[string]interface{}{
						"success": true,
						"message": "File fetched successfully",
						"file": &file,
					}, nil
				},
			},

			"sharedFiles": &graphql.Field{
				Type: filesResultType,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
							"files": nil,
						}, nil
					}

					var files []models.File
					err := database.DB.
						Preload("FileContent").
						Preload("User").
						Joins("JOIN file_shares ON file_shares.file_id = files.id").
						Where("file_shares.shared_with = ?", userID).
						Find(&files).Error

					if err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error fetching shared files: %v", err),
							"files": nil,
						}, nil
					}

					filePointers := make([]*models.File, len(files))
					for i := range files {
						filePointers[i] = &files[i]
					}

					return map[string]interface{}{
						"success": true,
						"message": "Shared files fetched successfully",
						"files": filePointers,
					}, nil
				},
			},

			"sharedFilesWithDetails": &graphql.Field{
				Type: fileSharesResultType,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
							"shares": nil,
						}, nil
					}

					var shares []models.FileShare
					err := database.DB.
						Preload("File").
						Preload("File.FileContent").
						Where("shared_with = ?", userID).
						Find(&shares).Error

					if err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error fetching shared files with details: %v", err),
							"shares": nil,
						}, nil
					}

					return map[string]interface{}{
						"success": true,
						"message": "Shared files with details fetched successfully",
						"shares": shares,
					}, nil
				},
			},

			"folders": &graphql.Field{
				Type: foldersResultType,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
							"folders": nil,
						}, nil
					}

					var folders []models.Folder
					err := database.DB.
						Where("user_id = ?", userID).
						Find(&folders).Error

					if err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error fetching folders: %v", err),
							"folders": nil,
						}, nil
					}

					return map[string]interface{}{
						"success": true,
						"message": "Folders fetched successfully",
						"folders": folders,
					}, nil
				},
			},

			"sharedFolders": &graphql.Field{
				Type: foldersResultType,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
							"folders": nil,
						}, nil
					}

					var shares []models.FolderShare
					err := database.DB.Where("shared_with = ?", userID).Find(&shares).Error
					if err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error fetching shared folder shares: %v", err),
							"folders": nil,
						}, nil
					}

					folderIDs := make([]string, len(shares))
					for i, share := range shares {
						folderIDs[i] = share.FolderID
					}

					var folders []models.Folder
					err = database.DB.
						Where("id IN (?)", folderIDs).
						Preload("User").
						Preload("Files").
						Preload("Files.FileContent").
						Find(&folders).Error

					if err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error fetching folders: %v", err),
							"folders": nil,
						}, nil
					}

					for i := range folders {
						var files []models.File
						err := database.DB.
							Preload("FileContent").
							Joins("JOIN folder_items ON folder_items.file_id = files.id").
							Where("folder_items.folder_id = ?", folders[i].ID).
							Find(&files).Error
						if err != nil {
							log.Printf("Error fetching files for folder %s: %v", folders[i].ID, err)
						}
						folders[i].Files = files
					}

					return map[string]interface{}{
						"success": true,
						"message": "Shared folders fetched successfully",
						"folders": folders,
					}, nil
				},
			},

			"storageStats": &graphql.Field{
				Type: storageStatsResultType,
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
							"stats": nil,
						}, nil
					}

					var totalUsed int64
					database.DB.Model(&models.FileContent{}).
						Joins("JOIN files ON files.file_content_id = file_contents.id").
						Where("files.user_id = ?", userID).
						Select("COALESCE(SUM(DISTINCT file_contents.file_size), 0)").
						Scan(&totalUsed)

					var originalSize int64
					database.DB.Model(&models.File{}).
						Joins("JOIN file_contents fc ON fc.id = files.file_content_id").
						Where("files.user_id = ?", userID).
						Select("COALESCE(SUM(fc.file_size), 0)").
						Scan(&originalSize)

					var fileCount, uniqueFileCount int64
					database.DB.Model(&models.File{}).
						Where("user_id = ?", userID).
						Count(&fileCount)

					database.DB.Model(&models.FileContent{}).
						Joins("JOIN files ON files.file_content_id = file_contents.id").
						Where("files.user_id = ?", userID).
						Distinct("file_contents.id").
						Count(&uniqueFileCount)

					saved := originalSize - totalUsed
					savedPercentage := 0.0
					if originalSize > 0 {
						savedPercentage = float64(saved) / float64(originalSize) * 100
					}

					stats := map[string]interface{}{
						"totalUsed": totalUsed,
						"originalSize": originalSize,
						"saved": saved,
						"savedPercentage": savedPercentage,
						"fileCount": fileCount,
						"uniqueFileCount": uniqueFileCount,
						"duplicateFileCount": fileCount - uniqueFileCount,
					}

					return map[string]interface{}{
						"success": true,
						"message": "Storage stats fetched successfully",
						"stats": stats,
					}, nil
				},
			},

		// allUsers resolver with database role check
"allUsers": &graphql.Field{
	Type: usersResultType,
	Resolve: func(p graphql.ResolveParams) (interface{}, error) {
		// Get the claims from the context
		userID, ok := p.Context.Value(authContextKey{}).(string)
		if !ok {
			return map[string]interface{}{
				"success": false,
				"message": "Not authenticated",
				"users": nil,
			}, nil
		}
		
		//  Use the userID from the claims to query the database for the user's role
		var user models.User
		if err := database.DB.Select("role").Where("id = ?", userID).First(&user).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return map[string]interface{}{
					"success": false,
					"message": "User not found.",
					"users": nil,
				}, nil
			}
			return map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Error fetching user role: %v", err),
				"users": nil,
			}, nil
		}
		
		//  Check if the role from the database is "admin"
		if user.Role != "admin" {
			return map[string]interface{}{
				"success": false,
				"message": "Access denied. Admin section.",
				"users": nil,
			}, nil
		}
		
		//  If the user is an admin, proceed to fetch all users
		var users []models.User
		if err := database.DB.Find(&users).Error; err != nil {
			return map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Error fetching all users: %v", err),
				"users": nil,
			}, nil
		}
		
		return map[string]interface{}{
			"success": true,
			"message": "Users fetched successfully",
			"users": users,
		}, nil
	},
},
		},
	})

	mutationType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			"shareFile": &graphql.Field{
				Type: operationResultType,
				Args: graphql.FieldConfigArgument{
					"fileId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"sharedWith": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"canEdit": &graphql.ArgumentConfig{Type: graphql.Boolean, DefaultValue: false},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
						}, nil
					}

					fileID := p.Args["fileId"].(string)
					sharedWith := p.Args["sharedWith"].(string)
					canEdit, _ := p.Args["canEdit"].(bool)

					var file models.File
					if err := database.DB.Where("id = ? AND user_id = ?", fileID, userID).First(&file).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": "File not found or access denied",
						}, nil
					}

					if strings.ToLower(sharedWith) == "public" {
						file.IsPublic = true
						if err := database.DB.Save(&file).Error; err != nil {
							return map[string]interface{}{
								"success": false,
								"message": fmt.Sprintf("Error making file public: %v", err),
							}, nil
						}
						return map[string]interface{}{
							"success": true,
							"message": "File shared publicly successfully",
						}, nil
					}

					var targetUser models.User
					if err := database.DB.Where("email = ?", sharedWith).First(&targetUser).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": "User not found",
						}, nil
					}

					share := models.FileShare{
						FileID: fileID,
						SharedBy: userID,
						SharedWith: targetUser.ID,
						CanEdit: canEdit,
					}

					if err := database.DB.Create(&share).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error sharing file: %v", err),
						}, nil
					}

					return map[string]interface{}{
						"success": true,
						"message": "File shared successfully",
					}, nil
				},
			},

			"unshareFile": &graphql.Field{
				Type: operationResultType,
				Args: graphql.FieldConfigArgument{
					"fileId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"sharedWith": &graphql.ArgumentConfig{Type: graphql.String},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
						}, nil
					}

					fileID := p.Args["fileId"].(string)
					sharedWith, hasSharedWith := p.Args["sharedWith"].(string)

					var file models.File
					if err := database.DB.Where("id = ? AND user_id = ?", fileID, userID).First(&file).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": "File not found or access denied",
						}, nil
					}

					if !hasSharedWith || strings.ToLower(sharedWith) == "public" {
						file.IsPublic = false
						if err := database.DB.Save(&file).Error; err != nil {
							return map[string]interface{}{
								"success": false,
								"message": fmt.Sprintf("Error making file private: %v", err),
							}, nil
						}
						return map[string]interface{}{
							"success": true,
							"message": "File made private successfully",
						}, nil
					}

					var targetUser models.User
					if err := database.DB.Where("email = ?", sharedWith).First(&targetUser).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": "User not found",
						}, nil
					}

					if err := database.DB.
						Where("file_id = ? AND shared_with = ? AND shared_by = ?", fileID, targetUser.ID, userID).
						Delete(&models.FileShare{}).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error unsharing file: %v", err),
						}, nil
					}

					return map[string]interface{}{
						"success": true,
						"message": "File unshared successfully",
					}, nil
				},
			},

			"deleteFile": &graphql.Field{
				Type: operationResultType,
				Args: graphql.FieldConfigArgument{
					"fileId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
						}, nil
					}

					fileID := p.Args["fileId"].(string)

					var file models.File
					if err := database.DB.Where("id = ? AND user_id = ?", fileID, userID).First(&file).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": "File not found or access denied",
						}, nil
					}

					if err := database.DB.Where("file_id = ?", fileID).Delete(&models.FileShare{}).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error deleting file shares: %v", err),
						}, nil
					}

					if err := database.DB.Where("file_id = ?", fileID).Delete(&models.FolderItem{}).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error removing file from folders: %v", err),
						}, nil
					}

					if err := database.DB.Delete(&file).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error deleting file: %v", err),
						}, nil
					}

					return map[string]interface{}{
						"success": true,
						"message": "File deleted successfully",
					}, nil
				},
			},
			"renameFile": &graphql.Field{
				Type: operationResultType,
				Args: graphql.FieldConfigArgument{
					"fileId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"newName": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{"success": false, "message": "Not authenticated"}, nil
					}

					fileID := p.Args["fileId"].(string)
					newName := p.Args["newName"].(string)

					var file models.File
					if err := database.DB.Where("id = ? AND user_id = ?", fileID, userID).First(&file).Error; err != nil {
						return map[string]interface{}{"success": false, "message": "File not found or access denied"}, nil
					}

					file.OriginalName = newName
					if err := database.DB.Save(&file).Error; err != nil {
						return map[string]interface{}{"success": false, "message": fmt.Sprintf("Error renaming file: %v", err)}, nil
					}

					return map[string]interface{}{"success": true, "message": "File renamed successfully"}, nil
				},
			},



"addTag": &graphql.Field{
    Type: operationResultType,
    Args: graphql.FieldConfigArgument{
        "fileId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
        "tag":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
    },
    Resolve: func(p graphql.ResolveParams) (interface{}, error) {
        userID, ok := p.Context.Value(authContextKey{}).(string)
        if !ok {
            return map[string]interface{}{
                "success": false,
                "message": "Not authenticated",
            }, nil
        }
        
        fileID := p.Args["fileId"].(string)
        newTag := strings.TrimSpace(p.Args["tag"].(string))
        if newTag == "" {
            return map[string]interface{}{
                "success": false,
                "message": "Tag cannot be empty",
            }, nil
        }
        var file models.File
        if err := database.DB.Where("id = ? AND user_id = ?", fileID, userID).First(&file).Error; err != nil {
            return map[string]interface{}{
                "success": false,
                "message": "File not found or access denied",
            }, nil
        }
        // Check if tag already exists
        for _, existingTag := range file.Tags {
            if existingTag == newTag {
                return map[string]interface{}{
                    "success": false,
                    "message": "Tag already exists",
                }, nil
            }
        }
        // Add the new tag
        file.Tags = append(file.Tags, newTag)
        if err := database.DB.Save(&file).Error; err != nil {
            return map[string]interface{}{
                "success": false,
                "message": fmt.Sprintf("Error adding tag: %v", err),
            }, nil
        }
        return map[string]interface{}{
            "success": true,
            "message": "Tag added successfully",
        }, nil
    },
},

// deleteTag mutation
"deleteTag": &graphql.Field{
    Type: operationResultType,
    Args: graphql.FieldConfigArgument{
        "fileId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
        "tag":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
    },
    Resolve: func(p graphql.ResolveParams) (interface{}, error) {
        userID, ok := p.Context.Value(authContextKey{}).(string)
        if !ok {
            return map[string]interface{}{
                "success": false,
                "message": "Not authenticated",
            }, nil
        }
        
        fileID := p.Args["fileId"].(string)
        tagToDelete := p.Args["tag"].(string)
        var file models.File
        if err := database.DB.Where("id = ? AND user_id = ?", fileID, userID).First(&file).Error; err != nil {
            return map[string]interface{}{
                "success": false,
                "message": "File not found or access denied",
            }, nil
        }
        // Find and remove the tag
        newTags := make([]string, 0)
        tagFound := false
        for _, existingTag := range file.Tags {
            if existingTag != tagToDelete {
                newTags = append(newTags, existingTag)
            } else {
                tagFound = true
            }
        }
        if !tagFound {
            return map[string]interface{}{
                "success": false,
                "message": "Tag not found",
            }, nil
        }
        file.Tags = pq.StringArray(newTags)
        if err := database.DB.Save(&file).Error; err != nil {
            return map[string]interface{}{
                "success": false,
                "message": fmt.Sprintf("Error deleting tag: %v", err),
            }, nil
        }
        return map[string]interface{}{
            "success": true,
            "message": "Tag deleted successfully",
        }, nil
    },
},
			"createFolder": &graphql.Field{
				Type: folderResultType,
				Args: graphql.FieldConfigArgument{
					"name": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"parentId": &graphql.ArgumentConfig{Type: graphql.String},
					"isPublic": &graphql.ArgumentConfig{Type: graphql.Boolean, DefaultValue: false},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
							"folder": nil,
						}, nil
					}

					name := p.Args["name"].(string)
					isPublic, _ := p.Args["isPublic"].(bool)
					parentId, hasParentID := p.Args["parentId"].(string)

					var existingFolder models.Folder
					if err := database.DB.Where("user_id = ? AND name = ?", userID, name).First(&existingFolder).Error; err == nil {
						return map[string]interface{}{
							"success": false,
							"message": "A folder with this name already exists",
							"folder": nil,
						}, nil
					} else if err != gorm.ErrRecordNotFound {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error checking existing folders: %v", err),
							"folder": nil,
						}, nil
					}

					folder := models.Folder{
						UserID: userID,
						Name: name,
						IsPublic: isPublic,
					}

					if hasParentID && parentId != "" {
						folder.ParentID = &parentId
					}

					if err := database.DB.Create(&folder).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error creating folder: %v", err),
							"folder": nil,
						}, nil
					}

					return map[string]interface{}{
						"success": true,
						"message": "Folder created successfully",
						"folder": folder,
					}, nil
				},
			},

			"addFileToFolder": &graphql.Field{
				Type: operationResultType,
				Args: graphql.FieldConfigArgument{
					"folderId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"fileId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
						}, nil
					}

					folderID := p.Args["folderId"].(string)
					fileID := p.Args["fileId"].(string)

					var folder models.Folder
					if err := database.DB.Where("id = ? AND user_id = ?", folderID, userID).First(&folder).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": "Folder not found or access denied",
						}, nil
					}

					var file models.File
					if err := database.DB.Where("id = ? AND user_id = ?", fileID, userID).First(&file).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": "File not found or access denied",
						}, nil
					}

					// ---  Check folder permissions and apply to file ---
					// Case 1: Folder is public.
					if folder.IsPublic {
						file.IsPublic = true
						if err := database.DB.Save(&file).Error; err != nil {
							return map[string]interface{}{"success": false, "message": fmt.Sprintf("Error making file public: %v", err)}, nil
						}
					}

					// Case 2: Folder is shared with specific users.
					var folderShares []models.FolderShare
					database.DB.Where("folder_id = ?", folderID).Find(&folderShares)
					for _, share := range folderShares {
						// Check if file is not already shared with this user
						var existingFileShare models.FileShare
						err := database.DB.Where("file_id = ? AND shared_with = ?", fileID, share.SharedWith).First(&existingFileShare).Error
						if err != nil && err == gorm.ErrRecordNotFound {
							fileShare := models.FileShare{
								FileID: fileID,
								SharedBy: userID,
								SharedWith: share.SharedWith,
								CanEdit: share.CanEdit,
							}
							if err := database.DB.Create(&fileShare).Error; err != nil {
								return map[string]interface{}{"success": false, "message": fmt.Sprintf("Error sharing file: %v", err)}, nil
							}
						}
					}
					// --- END NEW LOGIC ---

					folderItem := models.FolderItem{
						FolderID: folderID,
						FileID: fileID,
					}

					if err := database.DB.Create(&folderItem).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error adding file to folder: %v", err),
						}, nil
					}

					return map[string]interface{}{
						"success": true,
						"message": "File added to folder successfully",
					}, nil
				},
			},

			"updateFolder": &graphql.Field{
				Type: folderResultType,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"name": &graphql.ArgumentConfig{Type: graphql.String},
					"isPublic": &graphql.ArgumentConfig{Type: graphql.Boolean},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
							"folder": nil,
						}, nil
					}

					folderID := p.Args["id"].(string)
					var folder models.Folder
					if err := database.DB.Where("id = ? AND user_id = ?", folderID, userID).First(&folder).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": "Folder not found or access denied",
							"folder": nil,
						}, nil
					}
					
					// Check for name conflict if a new name is provided
					if name, ok := p.Args["name"].(string); ok && name != folder.Name {
						var existingFolder models.Folder
						if err := database.DB.Where("user_id = ? AND name = ?", userID, name).First(&existingFolder).Error; err == nil {
							return map[string]interface{}{
								"success": false,
								"message": "A folder with this name already exists",
								"folder": nil,
							}, nil
						} else if err != gorm.ErrRecordNotFound {
							return map[string]interface{}{
								"success": false,
								"message": fmt.Sprintf("Error checking existing folders: %v", err),
								"folder": nil,
							}, nil
						}
						folder.Name = name
					}

					// --- If public status is changing, update all files ---
					if isPublic, ok := p.Args["isPublic"].(bool); ok && isPublic != folder.IsPublic {
						folder.IsPublic = isPublic
						if err := database.DB.Model(&models.File{}).
							Joins("JOIN folder_items ON folder_items.file_id = files.id").
							Where("folder_items.folder_id = ?", folderID).
							Update("is_public", isPublic).Error; err != nil {
							return map[string]interface{}{
								"success": false,
								"message": fmt.Sprintf("Error updating files' public status: %v", err),
								"folder": nil,
							}, nil
						}
					}

					if err := database.DB.Save(&folder).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error updating folder: %v", err),
							"folder": nil,
						}, nil
					}

					return map[string]interface{}{
						"success": true,
						"message": "Folder updated successfully",
						"folder": folder,
					}, nil
				},
			},

			"deleteFolder": &graphql.Field{
				Type: operationResultType,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					userID, ok := p.Context.Value(authContextKey{}).(string)
					if !ok {
						return map[string]interface{}{
							"success": false,
							"message": "Not authenticated",
						}, nil
					}

					folderID := p.Args["id"].(string)
					var folder models.Folder
					if err := database.DB.Where("id = ? AND user_id = ?", folderID, userID).First(&folder).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": "Folder not found or access denied",
						}, nil
					}

					var filesToDelete []models.File
					if err := database.DB.
						Preload("FileContent").
						Joins("JOIN folder_items ON folder_items.file_id = files.id").
						Where("folder_items.folder_id = ?", folderID).
						Find(&filesToDelete).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error fetching folder items: %v", err),
						}, nil
					}

					for _, file := range filesToDelete {
						var otherReferences int64
						// Check if the file is in other folders
						database.DB.Model(&models.FolderItem{}).Where("file_id = ? AND folder_id != ?", file.ID, folderID).Count(&otherReferences)
						// Or if it's a standalone file not in any folder
						if otherReferences == 0 {
							// Check if file is still referenced by other users
							var fileReferenceCount int64
							database.DB.Model(&models.File{}).Where("file_content_id = ? AND id != ?", file.FileContentID, file.ID).Count(&fileReferenceCount)

							// If no other references exist, it's safe to delete the physical content
							if fileReferenceCount == 0 {
								// Delete from KvCache
								ctx := context.Background()
								if err := storage.DeleteFile(ctx, file.FileContent.StorageName); err != nil {
    log.Printf("Warning: Failed to delete physical file from R2 via Worker: %v", err)
}
								// Delete FileContent record
								if err := database.DB.Delete(&file.FileContent).Error; err != nil {
									log.Printf("Warning: Failed to delete file content record: %v", err)
								}
							}
							
							// Delete the file's shares
							database.DB.Where("file_id = ?", file.ID).Delete(&models.FileShare{})
							// Delete the File record
							database.DB.Delete(&file)
						}
					}

					// Delete all folder items for this folder
					if err := database.DB.Where("folder_id = ?", folderID).Delete(&models.FolderItem{}).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error deleting folder items: %v", err),
						}, nil
					}

					// Delete all folder shares for this folder
					if err := database.DB.Where("folder_id = ?", folderID).Delete(&models.FolderShare{}).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error deleting folder shares: %v", err),
						}, nil
					}

					// Finally, delete the folder record itself
					if err := database.DB.Delete(&folder).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error deleting folder: %v", err),
						}, nil
					}

					return map[string]interface{}{
						"success": true,
						"message": "Folder and related files deleted successfully",
					}, nil
				},
			},


			
			"shareFolder": &graphql.Field{
    Type: operationResultType,
    Args: graphql.FieldConfigArgument{
        "folderId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
        "sharedWith": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
    },
    Resolve: func(p graphql.ResolveParams) (interface{}, error) {
        userID, ok := p.Context.Value(authContextKey{}).(string)
        if !ok {
            return map[string]interface{}{"success": false, "message": "Not authenticated"}, nil
        }

        folderID := p.Args["folderId"].(string)
        sharedWithEmail := p.Args["sharedWith"].(string)

        var folder models.Folder
        if err := database.DB.Where("id = ? AND user_id = ?", folderID, userID).First(&folder).Error; err != nil {
            return map[string]interface{}{"success": false, "message": "Folder not found or access denied"}, nil
        }

        // Handle public sharing
        if strings.ToLower(sharedWithEmail) == "public" {
            if folder.IsPublic {
                return map[string]interface{}{"success": true, "message": "Folder is already public"}, nil
            }

            // Start a transaction to ensure atomicity
            tx := database.DB.Begin()
            defer tx.Rollback() // Rollback in case of error

            // 1. Update the folder's public status
            if err := tx.Model(&folder).Update("is_public", true).Error; err != nil {
                log.Printf("Error updating folder public status: %v", err)
                return map[string]interface{}{"success": false, "message": "Error updating folder"}, nil
            }

            // 2. Get the IDs of all files in the folder
            var fileIDs []string
            if err := tx.Model(&models.FolderItem{}).Where("folder_id = ?", folderID).Pluck("file_id", &fileIDs).Error; err != nil {
                log.Printf("Error getting file IDs for folder: %v", err)
                return map[string]interface{}{"success": false, "message": "Error getting file IDs"}, nil
            }

            // 3. Update the 'is_public' status for all those files
            if len(fileIDs) > 0 {
                if err := tx.Model(&models.File{}).Where("id IN (?)", fileIDs).Update("is_public", true).Error; err != nil {
                    log.Printf("Error updating files public status: %v", err)
                    return map[string]interface{}{"success": false, "message": "Error updating files"}, nil
                }
            }

            tx.Commit() // Commit the transaction
            return map[string]interface{}{"success": true, "message": "Folder and all its files shared publicly successfully"}, nil
        }
					// Handle user sharing
					var targetUser models.User
					if err := database.DB.Where("email = ?", sharedWithEmail).First(&targetUser).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": "User not found",
						}, nil
					}

					var existingShare models.FolderShare
					err := database.DB.Where("folder_id = ? AND shared_with = ?", folderID, targetUser.ID).First(&existingShare).Error
					if err == nil {
						return map[string]interface{}{
							"success": true,
							"message": "Folder is already shared with this user",
						}, nil
					}
					if err != gorm.ErrRecordNotFound {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error checking for existing share: %v", err),
						}, nil
					}

					share := models.FolderShare{
						FolderID: folderID,
						SharedBy: userID,
						SharedWith: targetUser.ID,
						CanEdit: false,
					}
					if err := database.DB.Create(&share).Error; err != nil {
						return map[string]interface{}{
							"success": false,
							"message": fmt.Sprintf("Error sharing folder: %v", err),
						}, nil
					}

					// Share all associated files with this user
					var filesToShare []models.File
					if err := database.DB.
						Joins("JOIN folder_items ON folder_items.file_id = files.id").
						Where("folder_items.folder_id = ?", folderID).
						Find(&filesToShare).Error; err != nil {
						log.Printf("Error fetching files to share: %v", err)
					}

					for _, file := range filesToShare {
						var existingFileShare models.FileShare
						if err := database.DB.Where("file_id = ? AND shared_with = ?", file.ID, targetUser.ID).First(&existingFileShare).Error; err != nil {
							if err == gorm.ErrRecordNotFound {
								fileShare := models.FileShare{
									FileID: file.ID,
									SharedBy: userID,
									SharedWith: targetUser.ID,
									CanEdit: false,
								}
								database.DB.Create(&fileShare)
							}
						}
					}

					return map[string]interface{}{
						"success": true,
						"message": "Folder shared successfully",
					}, nil
				},
			},

			"unshareFolder": &graphql.Field{
    Type: operationResultType,
    Args: graphql.FieldConfigArgument{
        "folderId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
        "sharedWith": &graphql.ArgumentConfig{Type: graphql.String},
    },
    Resolve: func(p graphql.ResolveParams) (interface{}, error) {
        userID, ok := p.Context.Value(authContextKey{}).(string)
        if !ok {
            return map[string]interface{}{
                "success": false,
                "message": "Not authenticated",
            }, nil
        }

        folderID := p.Args["folderId"].(string)
        sharedWith, hasSharedWith := p.Args["sharedWith"].(string)

        var folder models.Folder
        if err := database.DB.Where("id = ? AND user_id = ?", folderID, userID).First(&folder).Error; err != nil {
            return map[string]interface{}{
                "success": false,
                "message": "Folder not found or access denied",
            }, nil
        }

        // Get all file IDs within the folder
        var fileIDs []string
        database.DB.Model(&models.FolderItem{}).Where("folder_id = ?", folderID).Pluck("file_id", &fileIDs)
        
        // Scenario 1: Unshare from a specific user (by email)
        if hasSharedWith && sharedWith != "" && strings.ToLower(sharedWith) != "public" {
            var targetUser models.User
            if err := database.DB.Where("email = ?", sharedWith).First(&targetUser).Error; err != nil {
                return map[string]interface{}{
                    "success": false,
                    "message": "User not found",
                }, nil
            }

            // Delete the specific folder share record
            if err := database.DB.Where("folder_id = ? AND shared_with = ?", folderID, targetUser.ID).Delete(&models.FolderShare{}).Error; err != nil {
                return map[string]interface{}{"success": false, "message": fmt.Sprintf("Error unsharing folder: %v", err)}, nil
            }
            
            // Delete all associated file shares with this specific user
            if len(fileIDs) > 0 {
                if err := database.DB.Where("shared_with = ? AND file_id IN (?)", targetUser.ID, fileIDs).
                    Delete(&models.FileShare{}).Error; err != nil {
                    log.Printf("Error unsharing files for user: %v", err)
                }
            }
            
            return map[string]interface{}{
                "success": true,
                "message": "Folder unshared successfully with the specified user",
            }, nil
        }

        // Scenario 2 & 3: Unshare from public OR unshare from everyone
        // Delete all individual user shares for this folder
        if err := database.DB.Where("folder_id = ? AND shared_by = ?", folderID, userID).Delete(&models.FolderShare{}).Error; err != nil {
            log.Printf("Error deleting folder shares: %v", err)
        }

        // Make the folder private
        folder.IsPublic = false
        if err := database.DB.Save(&folder).Error; err != nil {
            return map[string]interface{}{
                "success": false,
                "message": fmt.Sprintf("Error making folder private: %v", err),
            }, nil
        }
        
        // Make all associated files private AND delete all file shares for files in this folder
        if len(fileIDs) > 0 {
             if err := database.DB.Where("file_id IN (?)", fileIDs).Delete(&models.FileShare{}).Error; err != nil {
                log.Printf("Error deleting file shares for folder: %v", err)
            }
            if err := database.DB.Model(&models.File{}).
                Where("id IN (?)", fileIDs).
                Update("is_public", false).Error; err != nil {
                return map[string]interface{}{
                    "success": false,
                    "message": fmt.Sprintf("Error making files private: %v", err),
                }, nil
            }
        }

        return map[string]interface{}{
            "success": true,
            "message": "Folder and all its files are now private",
        }, nil
    },
},
		},
	})

	schema, _ := graphql.NewSchema(graphql.SchemaConfig{
		Query: queryType,
		Mutation: mutationType,
	})

	return &schema
}

// Auth middleware for GraphQL
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

		// Attach the entire claims object to the context, so we can access the role
		ctx := context.WithValue(r.Context(), authContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}