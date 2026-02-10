package service

import (
	"os/exec"
)

// securityTools lists CLI tools to check for on the system PATH.
// Excludes curl/wget to encourage using sectool replay_send/request_send.
var securityTools = []string{
	// Network scanning and recon
	"nmap",
	"dig",
	"whois",

	// Web fuzzing and directory brute-force
	"ffuf",
	"dirb",
	"gobuster",
	"feroxbuster",
	"wfuzz",

	// Vulnerability scanners
	"nikto",
	"nuclei",
	"sqlmap",

	// HTTP utilities
	"httpx",

	// TLS/SSL testing
	"openssl",
	"sslyze",
	"testssl.sh",

	// Credential and hash attacks
	"hydra",
	"john",
	"hashcat",

	// Runtimes and utilities
	"python3",
	"python",
	"go",

	// Windows-common
	"certutil",
	"powershell",
}

// detectSystemTools returns the subset of securityTools found on PATH.
func detectSystemTools() []string {
	return detectSystemToolsWith(exec.LookPath)
}

// detectSystemToolsWith checks which tools are available using the provided lookup function.
func detectSystemToolsWith(lookPath func(string) (string, error)) []string {
	var found []string
	for _, tool := range securityTools {
		if _, err := lookPath(tool); err == nil {
			found = append(found, tool)
		}
	}
	return found
}
