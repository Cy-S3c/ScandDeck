package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/Cy-S3c/ScandDeck/internal/database"
	"github.com/Cy-S3c/ScandDeck/internal/discovery"
	"github.com/Cy-S3c/ScandDeck/internal/portscan"
	"github.com/Cy-S3c/ScandDeck/internal/service"
	"github.com/Cy-S3c/ScandDeck/pkg/config"
	"github.com/Cy-S3c/ScandDeck/pkg/target"
)

// ServerConfig holds the configuration for the HTTP server
type ServerConfig struct {
	Port           int
	StaticFilesDir string
	DatabasePath   string
}

// Server represents the HTTP server for ScandDeck
type Server struct {
	config     ServerConfig
	router     *mux.Router
	db         *database.DB
	httpServer *http.Server
}

// NewServer creates a new Server instance
func NewServer(cfg ServerConfig) (*Server, error) {
	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	server := &Server{
		config: cfg,
		router: mux.NewRouter(),
		db:     db,
	}

	server.initializeRoutes()
	return server, nil
}

// initializeRoutes sets up all the HTTP routes for the server
func (s *Server) initializeRoutes() {
	// API routes
	apiRouter := s.router.PathPrefix("/api").Subrouter()
	
	// Scan management endpoints
	apiRouter.HandleFunc("/scan", s.createScan).Methods("POST")
	apiRouter.HandleFunc("/scan/{id}", s.getScanStatus).Methods("GET")
	apiRouter.HandleFunc("/scan/{id}/stop", s.stopScan).Methods("POST")
	apiRouter.HandleFunc("/scan/list", s.listScans).Methods("GET")
	
	// Target management
	apiRouter.HandleFunc("/target", s.createTarget).Methods("POST")
	apiRouter.HandleFunc("/target/{id}", s.getTarget).Methods("GET")
	apiRouter.HandleFunc("/target/{id}", s.updateTarget).Methods("PUT")
	apiRouter.HandleFunc("/target/{id}", s.deleteTarget).Methods("DELETE")
	apiRouter.HandleFunc("/target/list", s.listTargets).Methods("GET")
	
	// Results and reporting
	apiRouter.HandleFunc("/result/scan/{id}", s.getScanResults).Methods("GET")
	apiRouter.HandleFunc("/result/host/{id}", s.getHostResults).Methods("GET")
	apiRouter.HandleFunc("/report/{id}", s.generateReport).Methods("GET")
	
	// Discovery related endpoints
	apiRouter.HandleFunc("/discovery", s.startDiscovery).Methods("POST")
	apiRouter.HandleFunc("/discovery/{id}", s.getDiscoveryStatus).Methods("GET")
	
	// Dashboard and statistics
	apiRouter.HandleFunc("/stats", s.getStatistics).Methods("GET")
	apiRouter.HandleFunc("/dashboard", s.getDashboardData).Methods("GET")
	
	// Static files for the web UI
	s.router.PathPrefix("/").Handler(http.FileServer(http.Dir(s.config.StaticFilesDir)))
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.config.Port)
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: s.router,
	}

	// Start server in a goroutine so it doesn't block
	go func() {
		log.Printf("Starting server on %s", addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error starting server: %v", err)
		}
	}()

	// Set up graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %v", err)
	}

	return nil
}

// Stop stops the HTTP server
func (s *Server) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// API Handlers

// createScan handles requests to start a new scan
func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var scanRequest struct {
		TargetIDs     []int            `json:"target_ids"`
		PortRanges    []string         `json:"port_ranges"`
		ScanType      string           `json:"scan_type"`
		ServiceDetect bool             `json:"service_detect"`
		Options       map[string]string `json:"options"`
	}

	if err := json.NewDecoder(r.Body).Decode(&scanRequest); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Get targets from database
	targets, err := s.db.GetTargetsByIDs(scanRequest.TargetIDs)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve targets: %v", err), http.StatusInternalServerError)
		return
	}

	// Create a new scan record
	scanID, err := s.db.CreateScan(targets, scanRequest.PortRanges, scanRequest.ScanType, scanRequest.Options)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create scan: %v", err), http.StatusInternalServerError)
		return
	}

	// Start scan in background
	go s.runScan(scanID, targets, scanRequest)

	// Return the scan ID
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id": scanID,
		"status":  "started",
	})
}

// runScan executes a scan in the background
func (s *Server) runScan(scanID int, targets []target.Target, request struct {
	TargetIDs     []int            `json:"target_ids"`
	PortRanges    []string         `json:"port_ranges"`
	ScanType      string           `json:"scan_type"`
	ServiceDetect bool             `json:"service_detect"`
	Options       map[string]string `json:"options"`
}) {
	// Update scan status to running
	s.db.UpdateScanStatus(scanID, "running")

	// Initialize scanner
	scanner := portscan.NewScanner()
	
	// Configure the scanner based on request options
	scannerConfig := &config.ScanConfig{
		ScanType:      request.ScanType,
		PortRanges:    request.PortRanges,
		Timeout:       5 * time.Second, // Default timeout
		ServiceDetect: request.ServiceDetect,
	}
	
	// Convert options to scanner config
	for k, v := range request.Options {
		switch k {
		case "timeout":
			if t, err := time.ParseDuration(v); err == nil {
				scannerConfig.Timeout = t
			}
		case "threads":
			// Handle thread count configuration
		}
	}

	// Run scan for each target
	var allResults []portscan.ScanResult
	for _, t := range targets {
		// Update progress in database
		s.db.UpdateScanProgress(scanID, fmt.Sprintf("Scanning %s", t.String()))
		
		// Run the actual scan
		results, err := scanner.Scan(t, scannerConfig)
		if err != nil {
			s.db.LogScanError(scanID, fmt.Sprintf("Error scanning %s: %v", t.String(), err))
			continue
		}
		
		// Store results
		s.db.StoreScanResults(scanID, t.ID, results)
		allResults = append(allResults, results...)
	}

	// If service detection is requested, run it
	if request.ServiceDetect && len(allResults) > 0 {
		s.db.UpdateScanProgress(scanID, "Running service detection")
		serviceDetector := service.NewDetector()
		
		for i, result := range allResults {
			if !result.Open {
				continue
			}
			
			s.db.UpdateScanProgress(scanID, fmt.Sprintf("Detecting service on %s:%d", result.IP, result.Port))
			serviceInfo, err := serviceDetector.Detect(result.IP, result.Port)
			if err != nil {
				s.db.LogScanError(scanID, fmt.Sprintf("Service detection error on %s:%d: %v", result.IP, result.Port, err))
				continue
			}
			
			// Update result with service info
			allResults[i].Service = serviceInfo.Name
			allResults[i].Version = serviceInfo.Version
			allResults[i].Banner = serviceInfo.Banner
			
			// Store updated result
			s.db.UpdateScanResult(scanID, result.IP, result.Port, serviceInfo)
		}
	}

	// Mark scan as completed
	s.db.UpdateScanStatus(scanID, "completed")
}

// getScanStatus returns the status of a scan
func (s *Server) getScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["id"]

	// Get scan status from database
	status, err := s.db.GetScanStatus(scanID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get scan status: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(status)
}

// stopScan stops an ongoing scan
func (s *Server) stopScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["id"]

	// Stop the scan - implementation depends on how scans are managed
	err := s.db.UpdateScanStatus(scanID, "cancelled")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to stop scan: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
}

// listScans returns a list of all scans
func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.db.GetAllScans()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list scans: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(scans)
}

// Target management handlers

// createTarget creates a new target
func (s *Server) createTarget(w http.ResponseWriter, r *http.Request) {
	var t target.Target
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate target
	if err := t.Validate(); err != nil {
		http.Error(w, fmt.Sprintf("Invalid target: %v", err), http.StatusBadRequest)
		return
	}

	// Store target in database
	id, err := s.db.CreateTarget(t)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create target: %v", err), http.StatusInternalServerError)
		return
	}

	t.ID = id
	json.NewEncoder(w).Encode(t)
}

// getTarget retrieves a target by ID
func (s *Server) getTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	t, err := s.db.GetTarget(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get target: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(t)
}

// updateTarget updates an existing target
func (s *Server) updateTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var t target.Target
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Update target in database
	err := s.db.UpdateTarget(id, t)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to update target: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// deleteTarget deletes a target
func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	err := s.db.DeleteTarget(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete target: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// listTargets returns a list of all targets
func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.db.GetAllTargets()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list targets: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(targets)
}

// Results and report handlers

// getScanResults returns the results of a scan
func (s *Server) getScanResults(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["id"]

	results, err := s.db.GetScanResults(scanID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get scan results: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(results)
}

// getHostResults returns the scan results for a specific host
func (s *Server) getHostResults

