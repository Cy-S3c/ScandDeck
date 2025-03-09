package database

import (
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB represents the database connection
type DB struct {
	conn *sql.DB
}

// ScanTarget represents a target to be scanned
type ScanTarget struct {
	ID        int64
	IP        string
	Hostname  string
	CreatedAt time.Time
}

// ScanResult represents the results of a scan
type ScanResult struct {
	ID          int64
	TargetID    int64
	ScanType    string // "port", "service", etc.
	Port        int
	Protocol    string // "tcp", "udp"
	ServiceName string
	Version     string
	Status      string // "open", "closed", "filtered"
	ScanTime    time.Time
}

// Insight represents an insight derived from scan results
type Insight struct {
	ID           int64
	TargetID     int64
	InsightType  string // "vulnerability", "misconfiguration", etc.
	Description  string
	Severity     string // "low", "medium", "high", "critical"
	References   string // JSON string of references
	CreatedAt    time.Time
}

// New creates a new database connection
func New(dataDir string) (*DB, error) {
	dbPath := filepath.Join(dataDir, "scandeck.db")
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection parameters
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(time.Hour)

	db := &DB{conn: conn}
	if err := db.initialize(); err != nil {
		conn.Close()
		return nil, err
	}

	return db, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// initialize creates the necessary tables if they don't exist
func (db *DB) initialize() error {
	// Create targets table
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS targets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			hostname TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create targets table: %w", err)
	}

	// Create scan_results table
	_, err = db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS scan_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target_id INTEGER NOT NULL,
			scan_type TEXT NOT NULL,
			port INTEGER,
			protocol TEXT,
			service_name TEXT,
			version TEXT,
			status TEXT NOT NULL,
			scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (target_id) REFERENCES targets (id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create scan_results table: %w", err)
	}

	// Create insights table
	_, err = db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS insights (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target_id INTEGER NOT NULL,
			insight_type TEXT NOT NULL,
			description TEXT NOT NULL,
			severity TEXT NOT NULL,
			references TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (target_id) REFERENCES targets (id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create insights table: %w", err)
	}

	// Create indexes for better performance
	_, err = db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_target_ip ON targets(ip)`)
	if err != nil {
		return fmt.Errorf("failed to create index on targets: %w", err)
	}

	_, err = db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results(target_id)`)
	if err != nil {
		return fmt.Errorf("failed to create index on scan_results: %w", err)
	}

	return nil
}

// AddTarget adds a new scan target to the database
func (db *DB) AddTarget(ip, hostname string) (int64, error) {
	result, err := db.conn.Exec(
		"INSERT INTO targets (ip, hostname, created_at) VALUES (?, ?, ?)",
		ip, hostname, time.Now(),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to add target: %w", err)
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert ID: %w", err)
	}
	
	return id, nil
}

// GetTarget retrieves a target by ID
func (db *DB) GetTarget(id int64) (*ScanTarget, error) {
	var target ScanTarget
	err := db.conn.QueryRow(
		"SELECT id, ip, hostname, created_at FROM targets WHERE id = ?",
		id,
	).Scan(&target.ID, &target.IP, &target.Hostname, &target.CreatedAt)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("target not found")
		}
		return nil, fmt.Errorf("failed to get target: %w", err)
	}
	
	return &target, nil
}

// GetTargetByIP retrieves a target by IP
func (db *DB) GetTargetByIP(ip string) (*ScanTarget, error) {
	var target ScanTarget
	err := db.conn.QueryRow(
		"SELECT id, ip, hostname, created_at FROM targets WHERE ip = ?",
		ip,
	).Scan(&target.ID, &target.IP, &target.Hostname, &target.CreatedAt)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("target not found")
		}
		return nil, fmt.Errorf("failed to get target: %w", err)
	}
	
	return &target, nil
}

// GetAllTargets retrieves all targets
func (db *DB) GetAllTargets() ([]*ScanTarget, error) {
	rows, err := db.conn.Query("SELECT id, ip, hostname, created_at FROM targets ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("failed to query targets: %w", err)
	}
	defer rows.Close()
	
	var targets []*ScanTarget
	for rows.Next() {
		var target ScanTarget
		if err := rows.Scan(&target.ID, &target.IP, &target.Hostname, &target.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan target row: %w", err)
		}
		targets = append(targets, &target)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating target rows: %w", err)
	}
	
	return targets, nil
}

// AddScanResult adds a new scan result
func (db *DB) AddScanResult(targetID int64, scanType string, port int, protocol, serviceName, version, status string) (int64, error) {
	result, err := db.conn.Exec(
		"INSERT INTO scan_results (target_id, scan_type, port, protocol, service_name, version, status, scan_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		targetID, scanType, port, protocol, serviceName, version, status, time.Now(),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to add scan result: %w", err)
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert ID: %w", err)
	}
	
	return id, nil
}

// GetScanResults retrieves scan results for a specific target
func (db *DB) GetScanResults(targetID int64) ([]*ScanResult, error) {
	rows, err := db.conn.Query(
		"SELECT id, target_id, scan_type, port, protocol, service_name, version, status, scan_time FROM scan_results WHERE target_id = ? ORDER BY scan_time DESC",
		targetID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query scan results: %w", err)
	}
	defer rows.Close()
	
	var results []*ScanResult
	for rows.Next() {
		var result ScanResult
		if err := rows.Scan(
			&result.ID, &result.TargetID, &result.ScanType, &result.Port, 
			&result.Protocol, &result.ServiceName, &result.Version, 
			&result.Status, &result.ScanTime,
		); err != nil {
			return nil, fmt.Errorf("failed to scan result row: %w", err)
		}
		results = append(results, &result)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating result rows: %w", err)
	}
	
	return results, nil
}

// AddInsight adds a new insight
func (db *DB) AddInsight(targetID int64, insightType, description, severity, references string) (int64, error) {
	result, err := db.conn.Exec(
		"INSERT INTO insights (target_id, insight_type, description, severity, references, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		targetID, insightType, description, severity, references, time.Now(),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to add insight: %w", err)
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert ID: %w", err)
	}
	
	return id, nil
}

// GetInsights retrieves insights for a specific target
func (db *DB) GetInsights(targetID int64) ([]*Insight, error) {
	rows, err := db.conn.Query(
		"SELECT id, target_id, insight_type, description, severity, references, created_at FROM insights WHERE target_id = ? ORDER BY created_at DESC",
		targetID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query insights: %w", err)
	}
	defer rows.Close()
	
	var insights []*Insight
	for rows.Next() {
		var insight Insight
		if err := rows.Scan(
			&insight.ID, &insight.TargetID, &insight.InsightType, 
			&insight.Description, &insight.Severity, &insight.References, 
			&insight.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan insight row: %w", err)
		}
		insights = append(insights, &insight)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating insight rows: %w", err)
	}
	
	return insights, nil
}

// GetAllInsights retrieves all insights
func (db *DB) GetAllInsights() ([]*Insight, error) {
	rows, err := db.conn.Query(
		"SELECT id, target_id, insight_type, description, severity, references, created_at FROM insights ORDER BY created_at DESC",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query all insights: %w", err)
	}
	defer rows.Close()
	
	var insights []*Insight
	for rows.Next() {
		var insight Insight
		if err := rows.Scan(
			&insight.ID, &insight.TargetID, &insight.InsightType, 
			&insight.Description, &insight.Severity, &insight.References, 
			&insight.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan insight row: %w", err)
		}
		insights = append(insights, &insight)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating insight rows: %w", err)
	}
	
	return insights, nil
}

// BatchAddScanResults adds multiple scan results in a single transaction
func (db *DB) BatchAddScanResults(results []*ScanResult) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	
	stmt, err := tx.Prepare("INSERT INTO scan_results (target_id, scan_type, port, protocol, service_name, version, status, scan_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()
	
	for _, result := range results {
		_, err := stmt.Exec(
			result.TargetID, result.ScanType, result.Port, 
			result.Protocol, result.ServiceName, result.Version, 
			result.Status, time.Now(),
		)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to execute statement: %w", err)
		}
	}
	
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	
	return nil
}

// DeleteOldScanResults deletes scan results older than a specific duration
func (db *DB) DeleteOldScanResults(age time.Duration) (int64, error) {
	cutoff := time.Now().Add(-age)
	
	result, err := db.conn.Exec("DELETE FROM scan_results WHERE scan_time < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old scan results: %w", err)
	}
	
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get affected rows: %w", err)
	}
	
	return affected, nil
}

// GetScanResultsByPort retrieves scan results for a specific port
func (db *DB) GetScanResultsByPort(port int, protocol string) ([]*ScanResult, error) {
	rows, err := db.conn.Query(
		"SELECT id, target_id, scan_type, port, protocol, service_name, version, status, scan_time FROM scan_results WHERE port = ? AND protocol = ? ORDER BY scan_time DESC",
		port, protocol,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query scan results by port: %w", err)
	}
	defer rows.Close()
	
	

