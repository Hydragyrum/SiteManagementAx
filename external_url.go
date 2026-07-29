package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const externalMaxFetchBytes = 10 * 1024 * 1024

type externalURLMetadata struct {
	Host        string
	Port        int
	URI         string
	SSL         bool
	FileName    string
	FileSize    int
	ContentType string
	FileB64     string
}

func createExternalSiteFromURL(rawURL string, operator string) (*HostedSite, error) {
	metadata, err := parseExternalURL(rawURL)
	if err != nil {
		return nil, err
	}

	return &HostedSite{
		URI:         metadata.URI,
		Host:        metadata.Host,
		Port:        metadata.Port,
		SSL:         metadata.SSL,
		ContentType: metadata.ContentType,
		FileName:    metadata.FileName,
		FileSize:    metadata.FileSize,
		FileB64:     metadata.FileB64,
		OneShot:     false,
		CreatedBy:   operator,
		CreatedAt:   time.Now().Unix(),
		Downloads:   0,
		Type:        SiteTypeExternal,
	}, nil
}

func parseExternalURL(rawURL string) (*externalURLMetadata, error) {
	clean := strings.TrimSpace(rawURL)
	if clean == "" {
		return nil, fmt.Errorf("url is required")
	}

	parsed, err := url.Parse(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("url scheme must be http or https")
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("url host is required")
	}
	if err := validateExternalHost(parsed.Hostname()); err != nil {
		return nil, err
	}

	host, port, uri, ssl := hostPortURI(parsed)
	if parsed.Port() != "" && (port < 1 || port > 65535) {
		return nil, fmt.Errorf("invalid port")
	}

	metadata := &externalURLMetadata{
		Host: host,
		Port: port,
		URI:  uri,
		SSL:  ssl,
	}
	metadata.FileName = fileNameFromPath(parsed.Path)
	metadata.ContentType = detectContentType(metadata.FileName)

	fetched, err := fetchExternalMetadata(clean)
	if err != nil {
		return nil, err
	}
	if fetched.Host != "" {
		metadata.Host = fetched.Host
		metadata.Port = fetched.Port
		metadata.URI = fetched.URI
		metadata.SSL = fetched.SSL
	}
	if fetched.ContentType != "" {
		metadata.ContentType = fetched.ContentType
	}
	if fetched.FileName != "" {
		metadata.FileName = fetched.FileName
	}
	if fetched.FileSize > 0 {
		metadata.FileSize = fetched.FileSize
	}
	metadata.FileB64 = fetched.FileB64

	return metadata, nil
}

func fetchExternalMetadata(rawURL string) (*externalURLMetadata, error) {
	requestURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if err := validateExternalHost(requestURL.Hostname()); err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					host = address
				}
				if err := validateExternalHost(host); err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, address)
			},
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			last := via[len(via)-1]
			if err := validateExternalHost(last.URL.Hostname()); err != nil {
				return err
			}
			return nil
		},
	}

	request, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(request)
	if err != nil || resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode >= 400 {
		if resp != nil {
			resp.Body.Close()
		}
		request, err = http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err = client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch external url: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("external url returned status %d", resp.StatusCode)
	}

	result := &externalURLMetadata{
		ContentType: contentTypeFromHeader(resp.Header.Get("Content-Type")),
		FileName:    fileNameFromHeader(resp.Header.Get("Content-Disposition")),
	}
	if resp.Request != nil && resp.Request.URL != nil {
		result.Host, result.Port, result.URI, result.SSL = hostPortURI(resp.Request.URL)
		if result.FileName == "" {
			result.FileName = fileNameFromPath(resp.Request.URL.Path)
		}
	}
	if lengthHeader := strings.TrimSpace(resp.Header.Get("Content-Length")); lengthHeader != "" {
		if fileSize, err := strconv.Atoi(lengthHeader); err == nil && fileSize >= 0 {
			result.FileSize = fileSize
		}
	}

	if resp.Request != nil && resp.Request.Method == http.MethodGet {
		body, err := io.ReadAll(io.LimitReader(resp.Body, externalMaxFetchBytes+1))
		if err != nil {
			return nil, fmt.Errorf("failed reading external content: %w", err)
		}
		if len(body) <= externalMaxFetchBytes {
			result.FileSize = len(body)
			result.FileB64 = base64.StdEncoding.EncodeToString(body)
			if result.FileName == "" && resp.Request.URL != nil {
				result.FileName = fileNameFromPath(resp.Request.URL.Path)
			}
		}
	}

	return result, nil
}

func hostPortURI(parsed *url.URL) (string, int, string, bool) {
	ssl := parsed.Scheme == "https"
	port := 80
	if ssl {
		port = 443
	}
	if parsed.Port() != "" {
		if parsedPort, err := strconv.Atoi(parsed.Port()); err == nil && parsedPort >= 1 && parsedPort <= 65535 {
			port = parsedPort
		}
	}
	uri := parsed.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	if parsed.RawQuery != "" {
		uri += "?" + parsed.RawQuery
	}
	return parsed.Hostname(), port, uri, ssl
}

func fileNameFromPath(pathValue string) string {
	base := path.Base(pathValue)
	if base == "." || base == "/" || base == "" {
		return "external.bin"
	}
	return base
}

func fileNameFromHeader(disposition string) string {
	if disposition == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		return ""
	}
	if fileName := strings.TrimSpace(params["filename"]); fileName != "" {
		return fileName
	}
	return ""
}

func contentTypeFromHeader(contentType string) string {
	trimmed := strings.TrimSpace(strings.Split(contentType, ";")[0])
	if trimmed == "" {
		return "application/octet-stream"
	}
	return trimmed
}

func validateExternalHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("url host is required")
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("external url host is not allowed")
	}

	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedIP(ip) {
			return fmt.Errorf("external url host is not allowed")
		}
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve url host: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("failed to resolve url host")
	}
	for _, ip := range ips {
		if isDisallowedIP(ip) {
			return fmt.Errorf("external url host is not allowed")
		}
	}
	return nil
}

func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}
