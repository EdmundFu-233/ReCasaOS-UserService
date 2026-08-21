package codeqlfixture

import (
	"io"
	"net/http"
	"os"
)

// UnsafeReadForMergeProtectionTest is intentionally vulnerable test evidence.
// This branch and pull request must never be merged.
func UnsafeReadForMergeProtectionTest(response http.ResponseWriter, request *http.Request) {
	file, err := os.Open(request.URL.Query().Get("path"))
	if err != nil {
		http.Error(response, "open failed", http.StatusBadRequest)
		return
	}
	defer file.Close()
	_, _ = io.Copy(response, file)
}
