package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var db *pgxpool.Pool

type ActivationRequest struct {
	Key      string `json:"key"`
	DeviceID string `json:"device_id"`
}

type ActivationResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	var err error
	db, err = pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer db.Close()

	http.HandleFunc("/activate", handleActivate)
	http.HandleFunc("/admin/reset", handleAdminReset)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("License server listening on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ActivationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existingDeviceID string
	var activatedAt time.Time
	err := db.QueryRow(ctx, "SELECT device_id, activated_at FROM licenses WHERE license_key = $1", req.Key).Scan(&existingDeviceID, &activatedAt)
	
	if err != nil { // Key does not exist in DB yet (fresh key)
		_, insertErr := db.Exec(ctx, "INSERT INTO licenses (license_key, device_id, activated_at) VALUES ($1, $2, NOW())", req.Key, req.DeviceID)
		if insertErr != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(ActivationResponse{Status: "activated"})
		return
	}

	// Key exists, check if it's the same device
	if existingDeviceID == req.DeviceID {
		json.NewEncoder(w).Encode(ActivationResponse{Status: "activated"})
	} else {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ActivationResponse{Status: "used", Error: "This key is already activated on another machine."})
	}
}

func handleAdminReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ActivationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := db.Exec(ctx, "UPDATE licenses SET device_id = NULL WHERE license_key = $1", req.Key)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
}