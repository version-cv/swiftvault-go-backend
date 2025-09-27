package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system.
type User struct {
	ID        string         `json:"id" gorm:"type:uuid;primaryKey;default:uuid_generate_v4()"`
	Email     string         `json:"email" gorm:"unique;not null"`
	Password  string         `json:"-" gorm:"not null"`
	Role      string         `json:"role" gorm:"default:user"`
	Plan      string         `json:"plan" gorm:"default:free"`
	Meta      JSONB          `json:"meta" gorm:"type:jsonb"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// JSONB is a custom type for handling JSONB fields in PostgreSQL
type JSONB map[string]interface{}

// Scan implements the sql.Scanner interface for JSONB
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(bytes, j)
}

// Value implements the driver.Valuer interface for JSONB
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}