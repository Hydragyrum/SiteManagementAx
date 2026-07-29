package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func handleHostGitlabFile(operator string, args string) {
	var req struct {
		Host        string `json:"host"`
		AccessToken string `json:"access_token"`
		Project     string `json:"project"`
		ContentType string `json:"content_type"`
		FileName    string `json:"file_name"`
		FileB64     string `json:"file_b64"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		sendError(operator, "Invalid args: "+err.Error())
		return
	}
	if req.Host == "" || req.AccessToken == "" || req.Project == "" || req.FileB64 == "" {
		sendError(operator, "host, access_token, project, and file_b64 are required")
		return
	}
	if strings.HasPrefix(req.Host, "http://") || strings.HasPrefix(req.Host, "https://") {
		sendError(operator, "host should not include http:// or https://")
		return
	}
	if req.ContentType == "" {
		req.ContentType = detectContentType(req.FileName)
	}

	fileBytes, err := base64.StdEncoding.DecodeString(req.FileB64)
	if err != nil {
		sendError(operator, "Invalid base64 file content: "+err.Error())
		return
	}
	if req.FileName == "" {
		req.FileName = "upload.bin"
	}

	uploadResp, statusCode, err := uploadFileToGitLab(req.Host, req.AccessToken, req.Project, req.FileName, fileBytes)
	if err != nil {
		if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
			notifyGitLabTokenRequired(operator, req.Host)
			return
		}
		sendError(operator, fmt.Sprintf("GitLab upload failed (%d): %s", statusCode, err.Error()))
		return
	}

	site := &HostedSite{
		URI: uploadResp.FullPath, Host: req.Host, Port: 443, SSL: true,
		ContentType: req.ContentType, FileName: req.FileName, FileSize: len(fileBytes),
		FileB64: req.FileB64, CreatedBy: operator, CreatedAt: time.Now().Unix(),
		Type: SiteTypeGitLab,
	}
	fmt.Printf("[FileHost] Hosted GitLab file: %s (%s, %d bytes) by %s\n",
		site.SiteKey(), site.ContentType, site.FileSize, operator)
	addHostedSite(site)
}

func handleUpdateGitlabToken(operator string, args string) {
	var req struct {
		Host         string `json:"host"`
		AccessToken  string `json:"access_token"`
		RetryPending bool   `json:"retry_pending"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		sendError(operator, "Invalid args: "+err.Error())
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	if req.Host == "" || req.AccessToken == "" {
		sendError(operator, "host and access_token are required")
		return
	}

	encryptedToken, err := encryptTokenWithPassAndSalt(TokenEncKeyPass, req.AccessToken)
	if err != nil {
		sendError(operator, "Failed to encrypt token: "+err.Error())
		return
	}
	tokenKey := gitLabTokenStoreKey(req.Host, operator)
	if err := Ts.TsExtenderDataSave("FileHost", tokenKey, []byte(encryptedToken)); err != nil {
		sendError(operator, "Failed to store token: "+err.Error())
		return
	}
	fmt.Printf("[FileHost] GitLab token updated host=%s operator=%s key=%s bytes=%d\n", req.Host, operator, tokenKey, len(encryptedToken))

	send(operator, map[string]any{
		"action": "gitlab_token_updated", "host": req.Host, "retry_pending": req.RetryPending,
	})
}

func handleGetGitlabToken(operator string, args string) {
	var req struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		sendError(operator, "Invalid args: "+err.Error())
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	if req.Host == "" {
		sendError(operator, "host is required")
		return
	}

	token, err := loadGitLabToken(req.Host, operator)
	if err != nil {
		return
	}
	send(operator, map[string]any{"action": "gitlab_token_value", "host": req.Host, "access_token": token})
}
