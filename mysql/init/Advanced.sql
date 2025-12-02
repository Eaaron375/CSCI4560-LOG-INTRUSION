DROP PROCEDURE IF EXISTS proc_scan_failed_logins;
DROP TRIGGER IF EXISTS trg_set_log_hash;
DROP TRIGGER IF EXISTS trg_bruteforce_alert;
DROP TRIGGER IF EXISTS trg_blacklist_ip;
/* ============================================================
   ADVANCED SQL FEATURES FOR IDS/IPS PROJECT
   ============================================================ */


/* ------------------------------------------------------------
   1. TRIGGER: Integrity Hash (Prevents Log Tampering)
   ------------------------------------------------------------ */
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


/* ------------------------------------------------------------
   2. TRIGGER: Brute Force Intrusion Detection
      (5+ failures in 10 minutes → auto alert)
   ------------------------------------------------------------ */
DELIMITER //
CREATE TRIGGER trg_bruteforce_alert
AFTER INSERT ON LOGINS
FOR EACH ROW
BEGIN
    IF NEW.status = 'failure' THEN
        IF (
            SELECT COUNT(*) 
            FROM LOGINS
            WHERE user_id = NEW.user_id
            AND status = 'failure'
            AND event_time >= NOW() - INTERVAL 10 MINUTE
        ) >= 5 THEN

            INSERT INTO ALERTS (log_id, alert_type, severity, description)
            VALUES (
                NEW.log_id,
                'Brute Force Login Attempt',
                'high',
                CONCAT('Multiple failed logins detected for user_id=', NEW.user_id)
            );

        END IF;
    END IF;
END;
//
DELIMITER ;


/* ------------------------------------------------------------
   3. TRIGGER: Auto-Blacklist Suspicious IPs
      (3 brute-force alerts from same IP → blacklist)
   ------------------------------------------------------------ */
DELIMITER //
CREATE TRIGGER trg_blacklist_ip
AFTER INSERT ON ALERTS
FOR EACH ROW
BEGIN
    IF NEW.alert_type = 'Brute Force Login Attempt' THEN

        IF (
            SELECT COUNT(*) 
            FROM ALERTS a
            JOIN LOGINS l ON a.log_id = l.log_id
            WHERE l.ip_address = (
                SELECT ip_address FROM LOGINS WHERE log_id = NEW.log_id
            )
            AND a.alert_type = 'Brute Force Login Attempt'
            AND a.created_at >= NOW() - INTERVAL 30 MINUTE
        ) >= 3 THEN

            INSERT IGNORE INTO IP_BLACKLIST (ip_address, reason)
            SELECT ip_address, 'Repeated brute force attacks'
            FROM LOGINS WHERE log_id = NEW.log_id;

        END IF;

    END IF;
END;
//
DELIMITER ;


/* ------------------------------------------------------------
   4. STORED PROCEDURE: Manual Batch Scan
      Finds users with 5+ fails in last 10 minutes
   ------------------------------------------------------------ */
DELIMITER //
CREATE PROCEDURE proc_scan_failed_logins()
BEGIN
    INSERT INTO ALERTS (log_id, alert_type, severity, description)
    SELECT 
        MAX(log_id),
        'Brute Force (Scan)',
        'medium',
        CONCAT('User ', user_id, ' has multiple failed attempts')
    FROM LOGINS
    WHERE status='failure'
      AND event_time >= NOW() - INTERVAL 10 MINUTE
    GROUP BY user_id
    HAVING COUNT(*) >= 5;
END;
//
DELIMITER ;

/* To run manually:
   CALL proc_scan_failed_logins();
*/


/* ------------------------------------------------------------
   5. WINDOW FUNCTIONS for Analytics / Dashboards
   ------------------------------------------------------------ */

-- 5a. Rolling fail count per user (10-minute window)
CREATE OR REPLACE VIEW vw_fail_trend AS
SELECT 
    user_id,
    event_time,
    status,
    COUNT(*) OVER (
        PARTITION BY user_id
        ORDER BY event_time
        RANGE BETWEEN INTERVAL 10 MINUTE PRECEDING AND CURRENT ROW
    ) AS rolling_fail_10min
FROM LOGINS;

-- 5b. Detect spikes by comparing to average
CREATE OR REPLACE VIEW vw_fail_spike AS
SELECT 
    user_id,
    event_time,
    status,
    COUNT(*) OVER w AS fail_count_window,
    AVG( (status='failure') ) OVER w AS avg_fail_rate
FROM LOGINS
WINDOW w AS (PARTITION BY user_id ORDER BY event_time ROWS 50 PRECEDING);

-- 5c. Daily login summary
CREATE OR REPLACE VIEW vw_daily_stats AS
SELECT
    DATE(event_time) AS day,
    COUNT(*) AS total_logins,
    SUM(status='failure') AS failures,
    SUM(status='success') AS successes,
    ROUND(AVG(status='failure')*100,2) AS failure_rate_percent
FROM LOGINS
GROUP BY day
ORDER BY day DESC;


/* ------------------------------------------------------------
   6. ADDITIONAL INDEXING
      Composite index for attacks from same IP + time
   ------------------------------------------------------------ */
CREATE INDEX idx_logins_ip_time ON LOGINS (ip_address, event_time);