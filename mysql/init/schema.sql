-- Drop existing tables if they exist
DROP TABLE IF EXISTS ALERTS;
DROP TABLE IF EXISTS LOGINS;
DROP TABLE IF EXISTS USERS;
DROP TABLE IF EXISTS IP_BLACKLIST;

-- USERS table
CREATE TABLE USERS (
    user_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    PRIMARY KEY (user_id)
) ENGINE=InnoDB;

-- LOGINS table
CREATE TABLE LOGINS (
    log_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT UNSIGNED NOT NULL,
    event_time DATETIME NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    status ENUM('success','failure') NOT NULL,
    processed TINYINT(1) DEFAULT 0,
    PRIMARY KEY (log_id),
    INDEX idx_logins_user_time (user_id, event_time),
    INDEX idx_logins_ip (ip_address),
    CONSTRAINT fk_logins_user FOREIGN KEY (user_id) REFERENCES USERS(user_id)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ALERTS table
CREATE TABLE ALERTS (
    alert_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    log_id BIGINT UNSIGNED,
    alert_type VARCHAR(50) NOT NULL,
    severity ENUM('low','medium','high') DEFAULT 'low',
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (alert_id),
    INDEX idx_alerts_log (log_id),
    CONSTRAINT fk_alerts_log FOREIGN KEY (log_id) REFERENCES LOGINS(log_id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- IP_BLACKLIST table
CREATE TABLE IP_BLACKLIST (
    ip_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255),
    date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ip_id)
) ENGINE=InnoDB;