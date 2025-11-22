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
    log_hash VARCHAR(128),  -- Added field for integrity hashing
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

-- IP_BLACKLIST (optional enrichment table)
CREATE TABLE IP_BLACKLIST (
    ip_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255),
    date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ip_id)
) ENGINE=InnoDB;



/* ----------------------------------------------------
TRIGGER #1: Integrity Hash (Prevents Tampering)
   ---------------------------------------------------- */
DELIMITER //
CREATE TRIGGER trg_set_log_hash
BEFORE INSERT ON LOGINS
FOR EACH ROW
BEGIN
  SET NEW.log_hash = SHA2(
      CONCAT(
          NEW.user_id, '|',
          NEW.ip_address, '|',
          NEW.event_time, '|',
          NEW.status
      ), 256);
END;
//
DELIMITER ;



/* ----------------------------------------------------
TRIGGER #2: Brute Force Intrusion Detection
   (5+ failed logins in 10 minutes)
   ---------------------------------------------------- */
DELIMITER //
CREATE TRIGGER trg_bruteforce_alert
AFTER INSERT ON LOGINS
FOR EACH ROW
BEGIN
    IF NEW.status = 'failure' THEN
        IF (
            SELECT COUNT(*) FROM LOGINS
            WHERE user_id = NEW.user_id
            AND status = 'failure'
            AND event_time >= NOW() - INTERVAL 10 MINUTE
        ) >= 5 THEN

            INSERT INTO ALERTS (log_id, alert_type, severity, description, created_at)
            VALUES (
                NEW.log_id,
                'Brute Force Login Attempt',
                'high',
                CONCAT('Multiple failed logins detected for user_id=', NEW.user_id),
                NOW()
            );

        END IF;
    END IF;
END;
//
DELIMITER ;



/* ----------------------------------------------------
STORED PROCEDURE: Manual Scan for Attacks
   ---------------------------------------------------- */
DELIMITER //
CREATE PROCEDURE proc_scan_failed_logins()
BEGIN
    INSERT INTO ALERTS (log_id, alert_type, severity, description, created_at)
    SELECT MAX(log_id), 'Brute Force (Scan)', 'medium',
           CONCAT('User ', user_id, ' has multiple failed attempts'),
           NOW()
    FROM LOGINS
    WHERE status='failure'
      AND event_time >= NOW() - INTERVAL 10 MINUTE
    GROUP BY user_id
    HAVING COUNT(*) >= 5;
END;
//
DELIMITER ;

-- To run manually:
-- CALL proc_scan_failed_logins();



/* ----------------------------------------------------
VIEW FOR GRAFANA DASHBOARDS
   ---------------------------------------------------- */
CREATE VIEW vw_security_overview AS
SELECT 
  l.log_id,
  u.username,
  l.ip_address,
  l.event_time,
  l.status,
  a.alert_type,
  a.severity,
  a.created_at AS alert_time
FROM LOGINS l
LEFT JOIN ALERTS a ON l.log_id = a.log_id
JOIN USERS u ON l.user_id = u.user_id
ORDER BY l.event_time DESC;

SELECT user, host FROM mysql.user;
    SHOW DATABASES;