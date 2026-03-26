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

-- ── generated_passwords ────────────────────────────────────
CREATE TABLE IF NOT EXISTS generated_passwords (
    id          INT           NOT NULL AUTO_INCREMENT,
    user_id     INT           NOT NULL,
    password    VARCHAR(512)  NOT NULL,
    length      INT           NOT NULL,
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_gen_user_id (user_id)
) ENGINE=InnoDB;

-- ── activity_logs ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_logs (
    id          INT           NOT NULL AUTO_INCREMENT,
    user_id     INT           NOT NULL,
    type        ENUM('success','error','info','warning') NOT NULL DEFAULT 'info',
    message     TEXT          NOT NULL,
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_log_user_id (user_id)
) ENGINE=InnoDB;

-- ── login_sessions ────────────────────────────────────────
-- Tracks every login event; used for multi-device alerting and
-- session revocation.
CREATE TABLE IF NOT EXISTS login_sessions (
    id          INT           NOT NULL AUTO_INCREMENT,
    user_id     INT           NOT NULL,
    session_id  VARCHAR(64)   NOT NULL UNIQUE,
    ip_address  VARCHAR(45)   NOT NULL,
    user_agent  VARCHAR(512)  NOT NULL,
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
    revoked     TINYINT(1)    NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sess_user_id (user_id),
    INDEX idx_sess_id      (session_id)
) ENGINE=InnoDB;
