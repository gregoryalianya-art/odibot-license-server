package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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

const secretKey = "OdibetsSuperSecretKey2026!"
const adminPassword = "Thecorrupt1.ke"

type ActivationRequest struct {
	Key      string `json:"key"`
	DeviceID string `json:"device_id"`
}

type ActivationResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Token  string `json:"token,omitempty"`
}

func generateToken(deviceID string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(deviceID))
	return hex.EncodeToString(mac.Sum(nil))
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
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/activate", handleActivate)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("License server listening on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ==========================================
// 1. THE DASHBOARD (Protected by Cookie)
// ==========================================
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Check for the login cookie
	cookie, err := r.Cookie("admin_session")
	if err != nil || cookie.Value != "authenticated" {
		// Not logged in. Show the login screen.
		showLoginPage(w, r.URL.Query().Get("error") == "1")
		return
	}

	// If we get here, the cookie is valid. Show the data.
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
			.btn { padding: 10px 20px; background: red; color: white; border: none; border-radius: 4px; float: right; cursor: pointer; }
		</style>
	</head>
	<body>
		<form action="/logout" method="POST"><button class="btn" type="submit">Logout</button></form>
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
// 2. LOGIN & LOGOUT
// ==========================================
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	if password == adminPassword {
		// Password correct: Set a secure HTTP-only cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_session",
			Value:    "authenticated",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400, // 1 day
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		// Password wrong: Redirect back with an error flag
		http.Redirect(w, r, "/?error=1", http.StatusSeeOther)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Delete the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func showLoginPage(w http.ResponseWriter, hasError bool) {
	errMsg := ""
	if hasError {
		errMsg = `<p style="color:red;">Incorrect password. Try again.</p>`
	}

	tmpl := `
	<html>
	<head>
		<title>Admin Login</title>
		<style>
			body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f4f4f9; margin: 0; }
			.login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); text-align: center; }
			input[type="password"] { padding: 10px; width: 250px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; }
			button { padding: 10px 20px; background: #333; color: white; border: none; border-radius: 4px; cursor: pointer; width: 270px; }
		</style>
	</head>
	<body>
		<div class="login-box">
			<h2>Admin Access</h2>
			` + errMsg + `
			<form action="/login" method="POST">
				<input type="password" name="password" placeholder="Enter admin password" required><br>
				<button type="submit">Login</button>
			</form>
		</div>
	</body>
	</html>`

	t, _ := template.New("login").Parse(tmpl)
	t.Execute(w, nil)
}

// ==========================================
// 3. THE ACTIVATION API (For the Bot)
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
		
		json.NewEncoder(w).Encode(ActivationResponse{
			Status: "activated", 
			Token: generateToken(req.DeviceID),
		})
		return
	}

	if *existingDeviceID == req.DeviceID {
		json.NewEncoder(w).Encode(ActivationResponse{
			Status: "activated", 
			Token: generateToken(req.DeviceID),
		})
	} else {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ActivationResponse{Status: "used", Error: "This key is already activated on another machine."})
	}
}
