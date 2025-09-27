-- Drop all existing tables in the correct order to avoid foreign key errors
DROP TABLE IF EXISTS folder_items;
DROP TABLE IF EXISTS file_shares;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS file_contents;

-- Create the users table
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL DEFAULT 'user',
    plan VARCHAR(255) NOT NULL DEFAULT 'free',
    meta JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_users_email ON users(email);

-- Create the new file_contents table for unique physical file data
CREATE TABLE file_contents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    storage_name VARCHAR(500) NOT NULL UNIQUE,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_file_contents_sha256_hash ON file_contents(sha256_hash);

-- Create the new files table for user-specific references
CREATE TABLE files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_content_id UUID NOT NULL REFERENCES file_contents(id) ON DELETE CASCADE,
    original_name VARCHAR(500) NOT NULL,
    is_public BOOLEAN DEFAULT FALSE,
    download_count INTEGER DEFAULT 0,
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_files_user_id ON files(user_id);
CREATE INDEX idx_files_file_content_id ON files(file_content_id);
CREATE INDEX idx_files_created_at ON files(created_at);

-- Recreate the other tables that depend on files and users
CREATE TABLE file_shares (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    shared_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    shared_with UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    can_edit BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(file_id, shared_with)
);
CREATE INDEX idx_file_shares_shared_with ON file_shares(shared_with);

CREATE TABLE folders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    parent_id UUID REFERENCES folders(id) ON DELETE CASCADE,
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_folders_user_id ON folders(user_id);

CREATE TABLE folder_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    folder_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(folder_id, file_id)
);

CREATE TABLE folder_shares (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    folder_id UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
    shared_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    shared_with UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    can_edit BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(folder_id, shared_with)
);
CREATE INDEX idx_folder_shares_shared_with ON folder_shares(shared_with);