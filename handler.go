package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SiteTypeDefault = 0
	SiteTypeGitLab  = 1
	tokenSaltSize   = 16
)

var errGitLabAuthRequired = errors.New("gitlab auth required")

type HostedSite struct {
	ID          string `json:"id"`
	URI         string `json:"uri"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	SSL         bool   `json:"ssl"`
	ContentType string `json:"content_type"`
	FileName    string `json:"file_name"`
	FileSize    int    `json:"file_size"`
	FileB64     string `json:"file_b64"`
	OneShot     bool   `json:"one_shot"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   int64  `json:"created_at"`
	Downloads   int    `json:"downloads"`
	Type        int    `json:"type"`
}

func (s *HostedSite) SiteKey() string {
	return MakeSiteKey(s.Host, s.Port, s.URI)
}

func (s *HostedSite) ServerKey() string {
	return MakeServerKey(s.Host, s.Port)
}

func (s *HostedSite) URL() string {
	scheme := "http"
	if s.SSL {
		scheme = "https"
	}
	host := s.Host
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, host, s.Port, s.URI)
}

func MakeSiteKey(host string, port int, uri string) string {
	return fmt.Sprintf("%s:%d%s", host, port, uri)
}

func MakeServerKey(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// ════════════════════════════════════════════════════════════════════════════
//  SiteManager
// ════════════════════════════════════════════════════════════════════════════

type SiteManager struct {
	mu    sync.RWMutex
	sites map[string]*HostedSite
}

func NewSiteManager() *SiteManager {
	return &SiteManager{
		sites: make(map[string]*HostedSite),
	}
}

func (sm *SiteManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sites)
}

func (sm *SiteManager) Get(key string) *HostedSite {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sites[key]
}

func (sm *SiteManager) List() []*HostedSite {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]*HostedSite, 0, len(sm.sites))
	for _, s := range sm.sites {
		result = append(result, s)
	}
	return result
}

func (sm *SiteManager) SitesOnServer(host string, port int) int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	prefix := MakeServerKey(host, port)
	count := 0
	for key := range sm.sites {
		if strings.HasPrefix(key, prefix) {
			count++
		}
	}
	return count
}

func (sm *SiteManager) Add(site *HostedSite) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sites[site.SiteKey()] = site
}

func (sm *SiteManager) Remove(key string) *HostedSite {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	site, ok := sm.sites[key]
	if !ok {
		return nil
	}
	delete(sm.sites, key)
	return site
}

func (sm *SiteManager) IncrementDownloads(key string) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	site, ok := sm.sites[key]
	if !ok {
		return 0
	}
	site.Downloads++
	return site.Downloads
}

func (sm *SiteManager) Persist(site *HostedSite) error {
	data, err := json.Marshal(site)
	if err != nil {
		return err
	}
	return Ts.TsExtenderDataSave("FileHost", "site:"+site.SiteKey(), data)
}

func (sm *SiteManager) Unpersist(siteKey string) error {
	return Ts.TsExtenderDataDelete("FileHost", "site:"+siteKey)
}

func (sm *SiteManager) RestoreAll() error {
	keys, err := Ts.TsExtenderDataKeys("FileHost")
	if err != nil {
		return err
	}

	for _, key := range keys {
		if !strings.HasPrefix(key, "site:") {
			continue
		}

		data, err := Ts.TsExtenderDataLoad("FileHost", key)
		if err != nil {
			fmt.Printf("[FileHost] WARNING: failed to load %s: %v\n", key, err)
			continue
		}

		var site HostedSite
		if err := json.Unmarshal(data, &site); err != nil {
			fmt.Printf("[FileHost] WARNING: failed to parse %s: %v\n", key, err)
			continue
		}

		if site.Host == "" || site.Port == 0 {
			fmt.Printf("[FileHost] WARNING: skipping legacy site %s (missing host/port)\n", key)
			continue
		}

		if site.Type == SiteTypeDefault {
			if _, err := Pool.GetOrStart(site.Host, site.Port, site.SSL); err != nil {
				fmt.Printf("[FileHost] WARNING: failed to start server for %s: %v\n", site.SiteKey(), err)
				continue
			}
		}

		sm.sites[site.SiteKey()] = &site
		fmt.Printf("[FileHost] Restored: %s (%s, %d bytes)\n", site.SiteKey(), site.ContentType, site.FileSize)
	}

	return nil
}

// ════════════════════════════════════════════════════════════════════════════
//  FileServer - per host:port HTTP(S) server
// ════════════════════════════════════════════════════════════════════════════

type FileServer struct {
	host string
	port int
	ssl  bool
	srv  *http.Server
}

func (fs *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.Path
	key := MakeSiteKey(fs.host, fs.port, uri)
	site := SiteMgr.Get(key)
	if site == nil {
		w.WriteHeader(404)
		return
	}

	fileBytes, err := base64.StdEncoding.DecodeString(site.FileB64)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	count := SiteMgr.IncrementDownloads(key)

	srcIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		srcIP = strings.Split(fwd, ",")[0]
	}
	userAgent := r.Header.Get("User-Agent")
	fmt.Printf("[FileHost] %s - %s - UA: %s - download #%d\n", key, srcIP, userAgent, count)

	broadcast(map[string]any{
		"action":   "download_event",
		"site_key": key,
		"count":    count,
	})

	if site.OneShot {
		go func() {
			time.Sleep(100 * time.Millisecond)
			removeSiteInternal(key)
			broadcast(map[string]any{
				"action":   "site_removed",
				"site_key": key,
				"reason":   "one-shot triggered",
			})
			fmt.Printf("[FileHost] One-shot: removed %s after serving\n", key)
			maybeStopServer(fs.host, fs.port)
		}()
	} else {
		go func() { _ = SiteMgr.Persist(site) }()
	}

	w.Header().Set("Content-Type", site.ContentType)
	if site.FileName != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, site.FileName))
	}
	http.ServeContent(w, r, "", time.Unix(site.CreatedAt, 0), bytes.NewReader(fileBytes))
}

// ════════════════════════════════════════════════════════════════════════════
//  ServerPool - manages file-serving HTTP(S) servers
// ════════════════════════════════════════════════════════════════════════════

type ServerPool struct {
	mu      sync.Mutex
	servers map[string]*FileServer
}

var Pool = &ServerPool{
	servers: make(map[string]*FileServer),
}

func (p *ServerPool) GetOrStart(host string, port int, ssl bool) (*FileServer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := MakeServerKey(host, port)
	if fs, ok := p.servers[key]; ok {
		if fs.ssl != ssl {
			scheme := "HTTP"
			if fs.ssl {
				scheme = "HTTPS"
			}
			return nil, fmt.Errorf("%s:%d already running as %s", host, port, scheme)
		}
		return fs, nil
	}

	fs := &FileServer{host: host, port: port, ssl: ssl}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	fs.srv = &http.Server{
		Addr:              addr,
		Handler:           fs,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if ssl {
		if SSLCert == "" || SSLKey == "" {
			return nil, fmt.Errorf("SSL cert/key not configured in service_config")
		}
		cert, err := tls.LoadX509KeyPair(SSLCert, SSLKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS cert/key: %v", err)
		}
		fs.srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		go fs.srv.ListenAndServeTLS("", "")
	} else {
		go fs.srv.ListenAndServe()
	}

	p.servers[key] = fs
	scheme := "http"
	if ssl {
		scheme = "https"
	}
	fmt.Printf("[FileHost] Started %s server on %s\n", scheme, addr)
	return fs, nil
}

func (p *ServerPool) Stop(host string, port int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := MakeServerKey(host, port)
	fs, ok := p.servers[key]
	if !ok {
		return
	}

	fs.srv.Close()
	delete(p.servers, key)
	fmt.Printf("[FileHost] Stopped server on %s:%d\n", host, port)
}

func maybeStopServer(host string, port int) {
	if SiteMgr.SitesOnServer(host, port) == 0 {
		Pool.Stop(host, port)
	}
}

// ════════════════════════════════════════════════════════════════════════════
//  Utilities
// ════════════════════════════════════════════════════════════════════════════

func getServerInterfaces() []string {
	result := []string{"0.0.0.0"}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return result
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP.String()
			if ip != "0.0.0.0" && ip != "::" {
				result = append(result, ip)
			}
		}
	}
	return result
}

func detectContentType(fileName string) string {
	ext := filepath.Ext(fileName)
	if ext != "" {
		if contentType := mime.TypeByExtension(ext); contentType != "" {
			return contentType
		}
	}
	return "application/octet-stream"
}

func removeSiteInternal(key string) {
	SiteMgr.Remove(key)
	SiteMgr.Unpersist(key)
}

func newTokenGCM(passphrase string, salt []byte) (cipher.AEAD, error) {
	key, err := deriveAES256Key(passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize gcm: %w", err)
	}
	return gcm, nil
}

func encryptTokenWithPassAndSalt(passphrase string, token string) (string, error) {
	if strings.TrimSpace(passphrase) == "" {
		return "", fmt.Errorf("token encryption passphrase is not configured")
	}

	salt := make([]byte, tokenSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	gcm, err := newTokenGCM(passphrase, salt)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(token), nil)
	payload := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	return base64.StdEncoding.EncodeToString(payload), nil
}

func decryptTokenWithPassAndSalt(passphrase string, encoded string) (string, error) {
	if strings.TrimSpace(passphrase) == "" {
		return "", fmt.Errorf("token encryption passphrase is not configured")
	}

	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid encrypted token format: %w", err)
	}
	if len(payload) <= tokenSaltSize {
		return "", fmt.Errorf("encrypted token payload is too short")
	}

	salt := payload[:tokenSaltSize]
	gcm, err := newTokenGCM(passphrase, salt)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(payload) <= tokenSaltSize+nonceSize {
		return "", fmt.Errorf("encrypted token payload is too short")
	}
	nonce := payload[tokenSaltSize : tokenSaltSize+nonceSize]
	ciphertext := payload[tokenSaltSize+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt token")
	}

	return string(plaintext), nil
}

type gitlabUploadResponse struct {
	ID       int64  `json:"id"`
	Alt      string `json:"alt"`
	URL      string `json:"url"`
	FullPath string `json:"full_path"`
	Markdown string `json:"markdown"`
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

	baseHost := strings.TrimSpace(host)
	if !strings.HasPrefix(baseHost, "http://") && !strings.HasPrefix(baseHost, "https://") {
		baseHost = "https://" + baseHost
	}
	baseHost = strings.TrimRight(baseHost, "/")

	projectEscaped := url.PathEscape(strings.TrimSpace(project))
	uploadURL := fmt.Sprintf("%s/api/v4/projects/%s/uploads", baseHost, projectEscaped)

	httpReq, err := http.NewRequest(http.MethodPost, uploadURL, &body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("PRIVATE-TOKEN", accessToken)
	httpReq.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
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

func notifyGitLabTokenRequired(operator string, host string, statusCode int, command string) {
	send(operator, map[string]any{
		"action":  "gitlab_token_required",
		"host":    strings.TrimSpace(host),
		"status":  statusCode,
		"command": command,
	})
}

func parseGitLabUploadPath(fullPath string) (project string, secret string, fileName string, err error) {
	parts := strings.Split(strings.Trim(strings.TrimSpace(fullPath), "/"), "/")
	// Expected: /-/project/<project>/uploads/<secret>/<filename>
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

func removeSiteFromGitLab(site *HostedSite, operator string) error {
	baseHost := strings.TrimSpace(site.Host)
	if !strings.HasPrefix(baseHost, "http://") && !strings.HasPrefix(baseHost, "https://") {
		baseHost = "https://" + baseHost
	}
	baseHost = strings.TrimRight(baseHost, "/")

	project, secret, fileName, err := parseGitLabUploadPath(site.URI)
	if err != nil {
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - %v\n", site.SiteKey(), err)
		return err
	}
	tokenKey := "gitlab_tokens:" + site.Host + ":" + operator
	fmt.Printf("[FileHost] GitLab remove attempt site=%s operator=%s host=%s project=%s file=%s token_key=%s\n",
		site.SiteKey(), operator, site.Host, project, fileName, tokenKey)

	tokenData, err := Ts.TsExtenderDataLoad("FileHost", tokenKey)
	if err != nil || len(tokenData) == 0 {
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - no token found for user %s\n", site.SiteKey(), operator)
		return fmt.Errorf("no gitlab token found")
	}
	fmt.Printf("[FileHost] GitLab remove token loaded key=%s bytes=%d\n", tokenKey, len(tokenData))

	decryptedToken, err := decryptTokenWithPassAndSalt(TokenEncKeyPass, string(tokenData))
	if err != nil {
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - failed to decrypt token for user %s: %v\n", site.SiteKey(), operator, err)
		return fmt.Errorf("failed to decrypt gitlab token")
	}

	deleteURL := fmt.Sprintf(
		"%s/api/v4/projects/%s/uploads/%s/%s",
		baseHost,
		url.PathEscape(project),
		url.PathEscape(secret),
		url.PathEscape(fileName),
	)
	fmt.Printf("[FileHost] GitLab remove request url=%s\n", deleteURL)

	httpReq, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	if err != nil {
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - failed to create request: %v\n", site.SiteKey(), err)
		return fmt.Errorf("failed to create delete request")
	}
	httpReq.Header.Set("PRIVATE-TOKEN", decryptedToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - request failed: %v\n", site.SiteKey(), err)
		return fmt.Errorf("gitlab delete request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Printf("[FileHost] GitLab remove response status=%d site=%s\n", resp.StatusCode, site.SiteKey())
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			notifyGitLabTokenRequired(operator, site.Host, resp.StatusCode, "remove_site")
			return errGitLabAuthRequired
		}
		fmt.Printf("[FileHost] WARNING: cannot remove GitLab site %s - request failed with status %d: %s\n", site.SiteKey(), resp.StatusCode, strings.TrimSpace(string(respBody)))
		return fmt.Errorf("gitlab delete failed with status %d", resp.StatusCode)
	}

	fmt.Printf("[FileHost] Successfully removed GitLab site %s by %s\n", site.SiteKey(), operator)
	return nil
}

// ════════════════════════════════════════════════════════════════════════════
//  Handlers
// ════════════════════════════════════════════════════════════════════════════

func handleHostFile(operator string, args string) {
	var req struct {
		URI         string `json:"uri"`
		Host        string `json:"host"`
		Port        int    `json:"port"`
		SSL         bool   `json:"ssl"`
		ContentType string `json:"content_type"`
		FileName    string `json:"file_name"`
		FileB64     string `json:"file_b64"`
		OneShot     bool   `json:"one_shot"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		sendError(operator, "Invalid args: "+err.Error())
		return
	}

	if req.URI == "" || req.FileB64 == "" || req.Host == "" || req.Port == 0 {
		sendError(operator, "uri, host, port, and file_b64 are required")
		return
	}

	if !strings.HasPrefix(req.URI, "/") {
		req.URI = "/" + req.URI
	}

	if req.ContentType == "" {
		req.ContentType = detectContentType(req.FileName)
	}

	siteKey := MakeSiteKey(req.Host, req.Port, req.URI)
	if SiteMgr.Get(siteKey) != nil {
		sendError(operator, "URI already hosted: "+siteKey)
		return
	}

	fileBytes, err := base64.StdEncoding.DecodeString(req.FileB64)
	if err != nil {
		sendError(operator, "Invalid base64 file content: "+err.Error())
		return
	}

	if _, err := Pool.GetOrStart(req.Host, req.Port, req.SSL); err != nil {
		sendError(operator, "Failed to start server: "+err.Error())
		return
	}

	site := &HostedSite{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		URI:         req.URI,
		Host:        req.Host,
		Port:        req.Port,
		SSL:         req.SSL,
		ContentType: req.ContentType,
		FileName:    req.FileName,
		FileSize:    len(fileBytes),
		FileB64:     req.FileB64,
		OneShot:     req.OneShot,
		CreatedBy:   operator,
		CreatedAt:   time.Now().Unix(),
		Downloads:   0,
		Type:        SiteTypeDefault,
	}

	SiteMgr.Add(site)

	if err := SiteMgr.Persist(site); err != nil {
		fmt.Printf("[FileHost] WARNING: failed to persist site %s: %v\n", site.SiteKey(), err)
	}

	fmt.Printf("[FileHost] Hosted: %s (%s, %d bytes, one-shot=%v) by %s\n",
		site.SiteKey(), site.ContentType, site.FileSize, site.OneShot, operator)

	broadcast(map[string]any{
		"action":       "site_added",
		"site_key":     site.SiteKey(),
		"uri":          site.URI,
		"host":         site.Host,
		"port":         site.Port,
		"ssl":          site.SSL,
		"content_type": site.ContentType,
		"file_name":    site.FileName,
		"file_size":    site.FileSize,
		"one_shot":     site.OneShot,
		"created_by":   site.CreatedBy,
		"created_at":   site.CreatedAt,
		"url":          site.URL(),
		"type":         site.Type,
	})
}

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
			notifyGitLabTokenRequired(operator, req.Host, statusCode, "host_gitlab_file")
			return
		}
		sendError(operator, fmt.Sprintf("GitLab upload failed (%d): %s", statusCode, err.Error()))
		return
	}

	site := &HostedSite{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		URI:         uploadResp.FullPath,
		Host:        req.Host,
		Port:        443,
		SSL:         true,
		ContentType: req.ContentType,
		FileName:    req.FileName,
		FileSize:    len(fileBytes),
		FileB64:     req.FileB64,
		OneShot:     false,
		CreatedBy:   operator,
		CreatedAt:   time.Now().Unix(),
		Downloads:   0,
		Type:        SiteTypeGitLab,
	}

	SiteMgr.Add(site)

	if err := SiteMgr.Persist(site); err != nil {
		fmt.Printf("[FileHost] WARNING: failed to persist site %s: %v\n", site.SiteKey(), err)
	}

	fmt.Printf("[FileHost] Hosted GitLab file: %s (%s, %d bytes) by %s\n",
		site.SiteKey(), site.ContentType, site.FileSize, operator)

	broadcast(map[string]any{
		"action":       "site_added",
		"site_key":     site.SiteKey(),
		"uri":          site.URI,
		"host":         site.Host,
		"port":         site.Port,
		"ssl":          site.SSL,
		"content_type": site.ContentType,
		"file_name":    site.FileName,
		"file_size":    site.FileSize,
		"one_shot":     site.OneShot,
		"created_by":   site.CreatedBy,
		"created_at":   site.CreatedAt,
		"url":          site.URL(),
		"type":         site.Type,
	})
}

func handleRemoveSite(operator string, args string) {
	var req struct {
		SiteKey string `json:"site_key"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil || req.SiteKey == "" {
		sendError(operator, "site_key is required")
		return
	}

	site := SiteMgr.Get(req.SiteKey)
	if site == nil {
		sendError(operator, "No site at: "+req.SiteKey)
		return
	}

	host, port := site.Host, site.Port
	switch site.Type {
	case SiteTypeDefault:
		maybeStopServer(host, port)
	case SiteTypeGitLab:
		if err := removeSiteFromGitLab(site, operator); err != nil {
			if errors.Is(err, errGitLabAuthRequired) {
				return
			}
			sendError(operator, "Failed to remove GitLab hosted file; saved site kept")
			return
		}
	default:
		fmt.Printf("[FileHost] WARNING: unknown site type %d for %s\n", site.Type, req.SiteKey)
		sendError(operator, "Unknown site type")
		return
	}
	removeSiteInternal(req.SiteKey)
	fmt.Printf("[FileHost] Removed: %s by %s\n", req.SiteKey, operator)

	broadcast(map[string]any{
		"action":   "site_removed",
		"site_key": req.SiteKey,
		"reason":   "operator removed",
	})
}

func handleGenerateAttack(operator string, args string) {
	var req struct {
		URL     string `json:"url"`
		Method  string `json:"method"`
		Encoded bool   `json:"encoded"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		sendError(operator, "Invalid args: "+err.Error())
		return
	}

	if req.URL == "" || req.Method == "" {
		sendError(operator, "url and method are required")
		return
	}

	script := GenerateOneliner(req.Method, req.URL, req.Encoded)
	if script == "" {
		sendError(operator, "Unknown attack method: "+req.Method)
		return
	}

	send(operator, map[string]any{
		"action": "attack_generated",
		"method": req.Method,
		"url":    req.URL,
		"script": script,
	})
}

func handleListSites(operator string) {
	sites := SiteMgr.List()
	siteList := make([]map[string]any, 0, len(sites))
	for _, s := range sites {
		siteList = append(siteList, map[string]any{
			"site_key":     s.SiteKey(),
			"uri":          s.URI,
			"host":         s.Host,
			"port":         s.Port,
			"ssl":          s.SSL,
			"content_type": s.ContentType,
			"file_name":    s.FileName,
			"file_size":    s.FileSize,
			"one_shot":     s.OneShot,
			"created_by":   s.CreatedBy,
			"created_at":   s.CreatedAt,
			"downloads":    s.Downloads,
			"url":          s.URL(),
			"type":         s.Type,
		})
	}

	send(operator, map[string]any{
		"action":     "sites_list",
		"sites":      siteList,
		"interfaces": getServerInterfaces(),
	})
}

func handleUpdateGitlabToken(operator string, args string) {
	var req struct {
		Host        string `json:"host"`
		AccessToken string `json:"access_token"`
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

	tokenKey := "gitlab_tokens:" + req.Host + ":" + operator
	//Update if Token exists, otherwise create a new entry
	if err := Ts.TsExtenderDataSave("FileHost", tokenKey, []byte(encryptedToken)); err != nil {
		sendError(operator, "Failed to store token: "+err.Error())
		return
	}
	fmt.Printf("[FileHost] GitLab token updated host=%s operator=%s key=%s bytes=%d\n", req.Host, operator, tokenKey, len(encryptedToken))

	send(operator, map[string]any{
		"action": "gitlab_token_updated",
		"host":   req.Host,
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

	tokenKey := "gitlab_tokens:" + req.Host + ":" + operator
	encryptedToken, err := Ts.TsExtenderDataLoad("FileHost", tokenKey)
	if err != nil {
		return
	}
	if len(encryptedToken) == 0 {
		return
	}
	fmt.Printf("[FileHost] GitLab token read host=%s operator=%s key=%s bytes=%d\n", req.Host, operator, tokenKey, len(encryptedToken))

	decryptedToken, err := decryptTokenWithPassAndSalt(TokenEncKeyPass, string(encryptedToken))
	if err != nil {
		sendError(operator, "Failed to decrypt token: "+err.Error())
		return
	}

	send(operator, map[string]any{
		"action":       "gitlab_token_value",
		"host":         req.Host,
		"access_token": decryptedToken,
	})
}
