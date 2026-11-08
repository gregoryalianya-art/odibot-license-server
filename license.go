package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const LicenseServerURL = "https://odibot-license-server-xyjw.vercel.app/activate"

func getDeviceID() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unknown-device"
	}
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 1 && i.Flags&net.FlagLoopback == 0 && len(i.HardwareAddr) >= 6 {
			return i.HardwareAddr.String()
		}
	}
	return "unknown-device"
}

func CheckLicense() {
	exeDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	licenseFile := filepath.Join(exeDir, ".activated")

	// 1. Check if already activated locally
	if data, err := os.ReadFile(licenseFile); err == nil {
		if string(data) == getDeviceID() {
			return // Already activated, proceed to the bot
		}
	}

	// 2. Show the Front Page
	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("                  LICENSE ACTIVATION")
	fmt.Println("============================================================")

	for {
		fmt.Print("Paste your activation key: ")
		key := readLine() // Uses the global reader from main.go
		if key == "" {
			continue
		}

		fmt.Println("Verifying key...")
		payload := map[string]string{
			"key":       key,
			"device_id": getDeviceID(),
		}
		jsonData, _ := json.Marshal(payload)

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Post(LicenseServerURL, "application/json", bytes.NewBuffer(jsonData))

		if err != nil {
			fmt.Println()
			fmt.Println("ERROR: Cannot connect to activation server. Check your internet.")
			fmt.Println()
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode == http.StatusOK {
			// Success!
			_ = os.WriteFile(licenseFile, []byte(getDeviceID()), 0644)
			fmt.Println()
			fmt.Println("✅ Success! License Activated.")
			fmt.Println("============================================================")
			fmt.Println()
			time.Sleep(1 * time.Second)
			return
		} else if resp.StatusCode == http.StatusConflict {
			// Used on another machine!
			fmt.Println()
			fmt.Println("============================================================")
			fmt.Println("  LICENSE KEY ALREADY USED")
			fmt.Println("============================================================")
			fmt.Println()
			fmt.Println("  This key has already been activated on another machine.")
			fmt.Println("  Each license key can only be used once.")
			fmt.Println()
			fmt.Println("  Contact us:  http://t.me/alexpimp")
			fmt.Println()
			fmt.Println("============================================================")
			fmt.Println()
			fmt.Println(">>> Press Enter to exit...")
			readLine()
			os.Exit(1) // Close program completely
		} else {
			// Other errors (e.g., Server Down)
			fmt.Println()
			fmt.Printf("ERROR: Server rejected the key. (Status: %d)\n", resp.StatusCode)
			fmt.Println(string(body))
			fmt.Println()
			fmt.Println("  Contact us:  http://t.me/alexpimp")
			fmt.Println(">>> Press Enter to exit...")
			readLine()
			os.Exit(1)
		}
	}
}
