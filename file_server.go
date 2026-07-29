package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FileServer struct {
	host string
	port int
	ssl  bool
	srv  *http.Server
}

func (fs *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := MakeSiteKey(fs.host, fs.port, r.URL.Path)
	site := SiteMgr.Get(key)
	if site == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	fileBytes, err := base64.StdEncoding.DecodeString(site.FileB64)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	count := SiteMgr.IncrementDownloads(key)
	srcIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		srcIP = strings.Split(forwarded, ",")[0]
	}
	fmt.Printf("[FileHost] %s - %s - UA: %s - download #%d\n", key, srcIP, r.Header.Get("User-Agent"), count)

	broadcast(map[string]any{"action": "download_event", "site_key": key, "count": count})

	if site.OneShot {
		go func() {
			time.Sleep(100 * time.Millisecond)
			removeSiteInternal(key)
			broadcast(map[string]any{"action": "site_removed", "site_key": key, "reason": "one-shot triggered"})
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

type ServerPool struct {
	mu      sync.Mutex
	servers map[string]*FileServer
}

var Pool = &ServerPool{servers: make(map[string]*FileServer)}

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
		fs.srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
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
	_ = fs.srv.Close()
	delete(p.servers, key)
	fmt.Printf("[FileHost] Stopped server on %s:%d\n", host, port)
}

func maybeStopServer(host string, port int) {
	if SiteMgr.SitesOnServer(host, port) == 0 {
		Pool.Stop(host, port)
	}
}

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
