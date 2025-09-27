package database

import (
	"log"
	"os"
	"backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto migrate the schema for all models
	err = DB.AutoMigrate(
		&models.User{},
		&models.FileContent{},
		&models.File{},
		&models.FileShare{},
		&models.Folder{},
		&models.FolderItem{},
		&models.FolderShare{},
	)
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	log.Println("Database connection established successfully")
}

