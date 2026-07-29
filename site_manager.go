package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

type SiteManager struct {
	mu    sync.RWMutex
	sites map[string]*HostedSite
}

func NewSiteManager() *SiteManager {
	return &SiteManager{sites: make(map[string]*HostedSite)}
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
	for _, site := range sm.sites {
		result = append(result, site)
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

		provider, ok := siteProviders[site.Type]
		if ok && provider.restore != nil {
			if err := provider.restore(&site); err != nil {
				fmt.Printf("[FileHost] WARNING: failed to restore %s: %v\n", site.SiteKey(), err)
				continue
			}
		}

		sm.sites[site.SiteKey()] = &site
		fmt.Printf("[FileHost] Restored: %s (%s, %d bytes)\n", site.SiteKey(), site.ContentType, site.FileSize)
	}
	return nil
}

func removeSiteInternal(key string) {
	SiteMgr.Remove(key)
	_ = SiteMgr.Unpersist(key)
}
