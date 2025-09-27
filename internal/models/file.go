package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lib/pq"

)

// FileContent represents the unique physical file stored in MinIO
type FileContent struct {
	ID          string    `json:"id" gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	StorageName string    `json:"storage_name" gorm:"not null;unique"`
	FileSize    int64     `json:"file_size" gorm:"not null"`
	MimeType    string    `json:"mime_type" gorm:"not null"`
	SHA256Hash  string    `json:"sha256_hash" gorm:"not null;unique;index"`
	CreatedAt   time.Time `json:"created_at"`
}

// File represents a user's reference to a file content
type File struct {
	ID            string      `json:"id" gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	UserID        string      `json:"user_id" gorm:"type:uuid;not null"`
	User          User        `json:"user" gorm:"foreignKey:UserID"`
	FileContentID string      `json:"file_content_id" gorm:"type:uuid;not null"`
	FileContent   FileContent `json:"file_content" gorm:"foreignKey:FileContentID"`
	OriginalName  string      `json:"original_name" gorm:"not null"`
	IsPublic      bool        `json:"is_public" gorm:"default:false"`
	DownloadCount int         `json:"download_count" gorm:"default:0"`
	Tags          pq.StringArray `json:"tags" gorm:"type:text[];default:'{}'"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

type StringArray []string

func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = StringArray{}
		return nil
	}
	
	switch v := value.(type) {
	case []byte:
		str := string(v)
		if str == "{}" {
			*a = StringArray{}
			return nil
		}
		str = strings.Trim(str, "{}")
		if str == "" {
			*a = StringArray{}
			return nil
		}
		parts := strings.Split(str, ",")
		for i, part := range parts {
			parts[i] = strings.TrimSpace(part)
		}
		*a = StringArray(parts)
		return nil
	case string:
		if v == "{}" {
			*a = StringArray{}
			return nil
		}
		v = strings.Trim(v, "{}")
		if v == "" {
			*a = StringArray{}
			return nil
		}
		parts := strings.Split(v, ",")
		for i, part := range parts {
			parts[i] = strings.TrimSpace(part)
		}
		*a = StringArray(parts)
		return nil
	default:
		return errors.New("unsupported type for StringArray")
	}
}

func (a StringArray) Value() (driver.Value, error) {
	if a == nil || len(a) == 0 {
		return "{}", nil
	}
	return "{" + strings.Join(a, ",") + "}", nil
}

func (a StringArray) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(a))
}

func (a *StringArray) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = StringArray(arr)
	return nil
}

// FileShare, Folder, and FolderItem structs remain unchanged
type FileShare struct {
    ID         string    `json:"id" gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
    FileID     string    `json:"file_id" gorm:"type:uuid;not null"`
    File       File      `json:"file" gorm:"foreignKey:FileID"`
    SharedBy   string    `json:"shared_by" gorm:"type:uuid;not null"`
    SharedWith string    `json:"shared_with" gorm:"type:uuid;not null"`
    CanEdit    bool      `json:"can_edit" gorm:"default:false"`
    CreatedAt  time.Time `json:"created_at"`
}

type Folder struct {
	ID        string    `json:"id" gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	UserID    string    `json:"user_id" gorm:"type:uuid;not null"`
	User      User      `json:"user" gorm:"foreignKey:UserID"`
	Name      string    `json:"name" gorm:"not null"`
	ParentID  *string   `json:"parent_id" gorm:"type:uuid"`
	IsPublic  bool      `json:"is_public" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Files     []File    `json:"files" gorm:"many2many:folder_items;foreignKey:ID;joinForeignKey:FolderID;References:ID;joinReferences:FileID"`
}

// --- NEW STRUCT ---
type FolderShare struct {
    ID         string    `json:"id" gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
    FolderID   string    `json:"folder_id" gorm:"type:uuid;not null"`
    Folder     Folder    `json:"folder" gorm:"foreignKey:FolderID"`
    SharedBy   string    `json:"shared_by" gorm:"type:uuid;not null"`
    SharedWith string    `json:"shared_with" gorm:"type:uuid;not null"`
    CanEdit    bool      `json:"can_edit" gorm:"default:false"`
    CreatedAt  time.Time `json:"created_at"`
}

type FolderItem struct {
    ID        string    `json:"id" gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
    FolderID  string    `json:"folder_id" gorm:"type:uuid;not null"`
    FileID    string    `json:"file_id" gorm:"type:uuid;not null"`
    File      File      `json:"file" gorm:"foreignKey:FileID"`
    CreatedAt time.Time `json:"created_at"`
}