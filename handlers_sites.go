package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"path/filepath"
	"strings"
	"time"
)

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
		URI: req.URI, Host: req.Host, Port: req.Port, SSL: req.SSL,
		ContentType: req.ContentType, FileName: req.FileName, FileSize: len(fileBytes),
		FileB64: req.FileB64, OneShot: req.OneShot, CreatedBy: operator,
		CreatedAt: time.Now().Unix(), Type: SiteTypeDefault,
	}
	fmt.Printf("[FileHost] Hosted: %s (%s, %d bytes, one-shot=%v) by %s\n",
		site.SiteKey(), site.ContentType, site.FileSize, site.OneShot, operator)
	addHostedSite(site)
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
	provider, ok := siteProviders[site.Type]
	if !ok || provider.remove == nil {
		fmt.Printf("[FileHost] WARNING: unknown site type %d for %s\n", site.Type, req.SiteKey)
		sendError(operator, "Unknown site type")
		return
	}
	if err := provider.remove(site, operator); err != nil {
		if errors.Is(err, errGitLabAuthRequired) {
			return
		}
		sendError(operator, provider.removeError)
		return
	}

	removeSiteInternal(req.SiteKey)
	fmt.Printf("[FileHost] Removed: %s by %s\n", req.SiteKey, operator)
	broadcast(map[string]any{"action": "site_removed", "site_key": req.SiteKey, "reason": "operator removed"})
}

func handleListSites(operator string, _ string) {
	sites := SiteMgr.List()
	siteList := make([]map[string]any, 0, len(sites))
	for _, site := range sites {
		siteList = append(siteList, sitePayload(site))
	}
	send(operator, map[string]any{"action": "sites_list", "sites": siteList, "interfaces": getServerInterfaces()})
}

func addHostedSite(site *HostedSite) {
	SiteMgr.Add(site)
	if err := SiteMgr.Persist(site); err != nil {
		fmt.Printf("[FileHost] WARNING: failed to persist site %s: %v\n", site.SiteKey(), err)
	}

	payload := sitePayload(site)
	payload["action"] = "site_added"
	broadcast(payload)
}

func detectContentType(fileName string) string {
	if contentType := mime.TypeByExtension(filepath.Ext(fileName)); contentType != "" {
		return contentType
	}
	return "application/octet-stream"
}
