package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type gitlabUploadResponse struct {
	FullPath string `json:"full_path"`
}

func uploadFileToGitLab(host string, accessToken string, project string, fileName string, fileBytes []byte) (*gitlabUploadResponse, int, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to build multipart upload: %w", err)
	}
	if _, err := part.Write(fileBytes); err != nil {
		return nil, 0, fmt.Errorf("failed to write multipart payload: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, 0, fmt.Errorf("failed to finalize multipart payload: %w", err)
	}

	baseHost := gitLabBaseURL(host)
	uploadURL := fmt.Sprintf("%s/api/v4/projects/%s/uploads", baseHost, url.PathEscape(strings.TrimSpace(project)))
	httpReq, err := http.NewRequest(http.MethodPost, uploadURL, &body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("PRIVATE-TOKEN", accessToken)
	httpReq.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("gitlab upload request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed reading gitlab response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("gitlab upload failed: %s", strings.TrimSpace(string(respBody)))
	}

	var uploadResp gitlabUploadResponse
	if err := json.Unmarshal(respBody, &uploadResp); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("gitlab upload succeeded but response JSON was invalid: %w", err)
	}
	return &uploadResp, resp.StatusCode, nil
}

func removeSiteFromGitLab(site *HostedSite, operator string) error {
	project, secret, fileName, err := parseGitLabUploadPath(site.URI)
	if err != nil {
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - %v\n", site.SiteKey(), err)
		return err
	}
	fmt.Printf("[FileHost] GitLab remove attempt site=%s operator=%s host=%s project=%s file=%s\n",
		site.SiteKey(), operator, site.Host, project, fileName)

	token, err := loadGitLabToken(site.Host, operator)
	if err != nil {
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - %v (user=%s)\n", site.SiteKey(), err, operator)
		return err
	}

	deleteURL := fmt.Sprintf("%s/api/v4/projects/%s/uploads/%s/%s",
		gitLabBaseURL(site.Host), url.PathEscape(project), url.PathEscape(secret), url.PathEscape(fileName))
	fmt.Printf("[FileHost] GitLab remove request url=%s\n", deleteURL)

	httpReq, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	if err != nil {
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - failed to create request: %v\n", site.SiteKey(), err)
		return fmt.Errorf("failed to create delete request")
	}
	httpReq.Header.Set("PRIVATE-TOKEN", token)

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(httpReq)
	if err != nil {
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - request failed: %v\n", site.SiteKey(), err)
		return fmt.Errorf("gitlab delete request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Printf("[FileHost] GitLab remove response status=%d site=%s\n", resp.StatusCode, site.SiteKey())
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			notifyGitLabTokenRequired(operator, site.Host)
			return errGitLabAuthRequired
		}
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - request failed with status %d: %s\n",
			site.SiteKey(), resp.StatusCode, strings.TrimSpace(string(respBody)))
		return fmt.Errorf("gitlab delete failed with status %d", resp.StatusCode)
	}

	fmt.Printf("[FileHost] Successfully removed GitLab site %s by %s\n", site.SiteKey(), operator)
	return nil
}

func gitLabBaseURL(host string) string {
	host = strings.TrimSpace(host)
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	return strings.TrimRight(host, "/")
}

func notifyGitLabTokenRequired(operator string, host string) {
	send(operator, map[string]any{"action": "gitlab_token_required", "host": strings.TrimSpace(host)})
}

func gitLabTokenStoreKey(host string, operator string) string {
	return "gitlab_tokens:" + strings.TrimSpace(host) + ":" + operator
}

func loadGitLabToken(host string, operator string) (string, error) {
	tokenKey := gitLabTokenStoreKey(host, operator)
	tokenData, err := Ts.TsExtenderDataLoad("FileHost", tokenKey)
	if err != nil || len(tokenData) == 0 {
		return "", fmt.Errorf("no gitlab token found")
	}
	fmt.Printf("[FileHost] GitLab token read host=%s operator=%s key=%s bytes=%d\n", host, operator, tokenKey, len(tokenData))

	token, err := decryptTokenWithPassAndSalt(TokenEncKeyPass, string(tokenData))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt gitlab token")
	}
	return token, nil
}

func parseGitLabUploadPath(fullPath string) (project string, secret string, fileName string, err error) {
	parts := strings.Split(strings.Trim(strings.TrimSpace(fullPath), "/"), "/")
	if len(parts) != 6 || parts[0] != "-" || parts[1] != "project" || parts[3] != "uploads" {
		return "", "", "", fmt.Errorf("invalid gitlab upload path: %s", fullPath)
	}

	project, err = url.PathUnescape(parts[2])
	if err != nil {
		project = parts[2]
	}
	secret, err = url.PathUnescape(parts[4])
	if err != nil {
		secret = parts[4]
	}
	fileName, err = url.PathUnescape(parts[5])
	if err != nil {
		fileName = parts[5]
	}
	return project, secret, fileName, nil
}
