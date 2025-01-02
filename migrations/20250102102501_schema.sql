-- Users table to store basic user information
CREATE TABLE users (
    id BINARY(16) PRIMARY KEY,                    -- UUID stored as binary
    username VARCHAR(255) UNIQUE NOT NULL,        -- Unique username for login
    email VARCHAR(255) UNIQUE NOT NULL,           -- Unique email address
    display_name VARCHAR(255) NOT NULL,           -- User's display name
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP -- Account creation timestamp
);

-- Registration state table for storing temporary WebAuthn registration data
CREATE TABLE registration_state (
    id BINARY(16) PRIMARY KEY,                    -- UUID stored as binary
    user_id BINARY(16) NOT NULL,                  -- Reference to users table
    passkey_registration BLOB NOT NULL,           -- Serialized registration data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,-- Registration attempt timestamp
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

