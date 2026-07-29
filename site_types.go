package main

import (
	"errors"
	"fmt"
)

const (
	SiteTypeDefault = 0
	SiteTypeGitLab  = 1
)

var errGitLabAuthRequired = errors.New("gitlab auth required")

type HostedSite struct {
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

type siteProvider struct {
	restore     func(*HostedSite) error
	remove      func(*HostedSite, string) error
	removeError string
}

var siteProviders = map[int]siteProvider{
	SiteTypeDefault: {
		restore: func(site *HostedSite) error {
			_, err := Pool.GetOrStart(site.Host, site.Port, site.SSL)
			return err
		},
		remove: func(site *HostedSite, _ string) error {
			maybeStopServer(site.Host, site.Port)
			return nil
		},
	},
	SiteTypeGitLab: {
		remove:      removeSiteFromGitLab,
		removeError: "Failed to remove GitLab hosted file; saved site kept",
	},
}

func sitePayload(site *HostedSite) map[string]any {
	return map[string]any{
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
		"downloads":    site.Downloads,
		"url":          site.URL(),
		"type":         site.Type,
	}
}
