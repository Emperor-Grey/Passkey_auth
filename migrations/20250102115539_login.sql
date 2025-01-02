-- Passkeys table for storing user's registered passkeys
CREATE TABLE passkeys (
    id BINARY(16) PRIMARY KEY,                    -- UUID stored as binary
    user_id BINARY(16) NOT NULL,                  -- Reference to users table
    passkey BLOB NOT NULL,                        -- Serialized passkey data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,-- Passkey creation timestamp
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Authentication state table for storing temporary WebAuthn authentication data
CREATE TABLE auth_state (
    id BINARY(16) PRIMARY KEY,                    -- UUID stored as binary
    user_id BINARY(16) NOT NULL,                  -- Reference to users table
    auth_state BLOB NOT NULL,                     -- Serialized authentication state
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,-- Authentication attempt timestamp
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
