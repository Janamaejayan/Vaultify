-- ============================================================
--  Vaultify — Database Schema
--  Run once to initialise the MySQL database.
--  Usage: mysql -u root -p < schema.sql
-- ============================================================

CREATE DATABASE IF NOT EXISTS vaultify
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE vaultify;

-- ── users ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INT          NOT NULL AUTO_INCREMENT,
    username      VARCHAR(80)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB;

-- ── passwords ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS passwords (
    id                 INT          NOT NULL AUTO_INCREMENT,
    user_id            INT          NOT NULL,
    site               VARCHAR(120) NOT NULL,
    site_username      VARCHAR(120) NOT NULL,
    encrypted_password TEXT         NOT NULL,   -- Fernet-encrypted, base64-encoded
    created_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                    ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB;
