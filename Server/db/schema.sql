-- ==========================================================
-- Clean database setup for Secure Email App (S/MIME style)
-- ==========================================================

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS email_app
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE email_app;

-- ==========================================================
-- Drop existing tables (to recreate cleanly)
-- ==========================================================
DROP TABLE IF EXISTS attachments;
DROP TABLE IF EXISTS emails;
DROP TABLE IF EXISTS user_keys;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS system_keys;

-- ==========================================================
-- Create tables
-- ==========================================================

-- 1️⃣ USERS TABLE
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  public_key TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 3️⃣ EMAILS TABLE
CREATE TABLE emails (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sender_id INT NOT NULL,
  recipient_id INT NOT NULL,

  encrypted_key_sender TEXT NOT NULL,
  encrypted_key_recipient TEXT NOT NULL,
  encrypted_key_ml TEXT NULL,
  ciphertext LONGTEXT NOT NULL,
  iv TEXT NOT NULL,
  
  ml_scan_status ENUM('PENDING', 'SCANNED', 'FAILED') DEFAULT 'PENDING',
  ml_spam_result ENUM('SPAM', 'HAM') DEFAULT 'HAM',
  ml_spam_score FLOAT NULL,
  ml_sentiment_result ENUM('POSITIVE', 'NEGATIVE', 'NEUTRAL') DEFAULT 'NEUTRAL',
  ml_sentiment_score FLOAT NULL,

  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (sender_id) REFERENCES users(id),
  FOREIGN KEY (recipient_id) REFERENCES users(id),
  
	-- ADD INDEX HERE
  INDEX idx_spam_result (ml_spam_result),
  INDEX idx_sentiment_label (ml_sentiment_result),
  INDEX idx_scan_status (ml_scan_status)
);

CREATE TABLE system_keys (
  id INT PRIMARY KEY AUTO_INCREMENT,
  service_name VARCHAR(100) UNIQUE NOT NULL,   -- ví dụ 'ml_service'
  public_key TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO system_keys (service_name, public_key)
VALUES (
'ml_service', 
'-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsAwxbZeCcrulmqgxX3qs
Df9CzLNHRet73Vb2zUycmXms56+QW4xFr1/jeFvP4HFGi/UZRmgqu6Xhm1SAEvJW
Ep2X1lmlZDSK42H3bcKAXR2j0fpqpiEnZ1hPHxVcJ6mq0GHIH7g7RKJft4SLBs7y
LN0c3DnphPiugsgv3UEfCZSDXYW01TGpQgVce7AKaWNgabudA3x7g7rOJdudT5yF
owrMDTrK1OKINKqh/4ArP+oCzBuG5QsZnxLGD5WYJM4u9MOIZjmQrLntZ6FVTSms
bFiif9sGc3wHiymlL9nBDd/cYopAYls7aqIqsny4xExQaRVbyPfAmGEhNUEpnHp1
1wIDAQAB
-----END PUBLIC KEY-----'
);



-- ==========================================================
-- Done! ✅
-- ==========================================================
