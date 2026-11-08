package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
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

	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/activate", handleActivate)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("License server listening on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ==========================================
// 1. THE DASHBOARD (To view keys)
// ==========================================
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Simple password protection (Change "admin123" to whatever you want)
	if r.URL.Query().Get("pass") != "admin123" {
		http.Error(w, "Unauthorized. Add ?pass=admin123 to the URL", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query(context.Background(), "SELECT license_key, device_id FROM licenses ORDER BY activated_at DESC NULLS LAST, license_key ASC")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type KeyData struct {
		Key    string
		Status string
	}
	var keys []KeyData

	for rows.Next() {
		var key string
		var deviceID *string
		if err := rows.Scan(&key, &deviceID); err != nil {
			continue
		}
		status := "🟢 Available (Unused)"
		if deviceID != nil {
			status = "🔴 Used (" + *deviceID + ")"
		}
		keys = append(keys, KeyData{Key: key, Status: status})
	}

	// Render HTML
	tmpl := `
	<html>
	<head>
		<title>License Dashboard</title>
		<style>
			body { font-family: sans-serif; padding: 20px; background: #f4f4f9; }
			table { border-collapse: collapse; width: 100%; max-width: 800px; background: white; }
			th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
			th { background: #333; color: white; }
			.used { color: red; }
			.avail { color: green; font-weight: bold; }
			input { padding: 8px; width: 300px; margin-bottom: 20px; }
		</style>
	</head>
	<body>
		<h2>License Key Dashboard</h2>
		<input type="text" id="search" onkeyup="filterTable()" placeholder="Search for keys...">
		<table id="keyTable">
			<tr><th>License Key</th><th>Status</th></tr>
			{{range .}}
			<tr>
				<td>{{.Key}}</td>
				<td class="{{if eq .Status "Available"}}avail{{else}}used{{end}}">{{.Status}}</td>
			</tr>
			{{end}}
		</table>
		<script>
			function filterTable() {
				var input, filter, table, tr, td, i, txtValue;
				input = document.getElementById("search");
				filter = input.value.toUpperCase();
				table = document.getElementById("keyTable");
				tr = table.getElementsByTagName("tr");
				for (i = 0; i < tr.length; i++) {
					td = tr[i].getElementsByTagName("td")[0];
					if (td) {
						txtValue = td.textContent || td.innerText;
						if (txtValue.toUpperCase().indexOf(filter) > -1) {
							tr[i].style.display = "";
						} else {
							tr[i].style.display = "none";
						}
					}
				}
			}
		</script>
	</body>
	</html>`

	t, _ := template.New("dash").Parse(tmpl)
	t.Execute(w, keys)
}

// ==========================================
// 2. THE ACTIVATION API (For the Bot)
// ==========================================
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

	var existingDeviceID *string
	var activatedAt time.Time
	err := db.QueryRow(ctx, "SELECT device_id, activated_at FROM licenses WHERE license_key = $1", req.Key).Scan(&existingDeviceID, &activatedAt)
	
	if err != nil { 
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ActivationResponse{Status: "invalid", Error: "Invalid license key."})
		return
	}

	if existingDeviceID == nil {
		_, updateErr := db.Exec(ctx, "UPDATE licenses SET device_id = $1, activated_at = NOW() WHERE license_key = $2", req.DeviceID, req.Key)
		if updateErr != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(ActivationResponse{Status: "activated"})
		return
	}

	if *existingDeviceID == req.DeviceID {
		json.NewEncoder(w).Encode(ActivationResponse{Status: "activated"})
	} else {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ActivationResponse{Status: "used", Error: "This key is already activated on another machine."})
	}
}
