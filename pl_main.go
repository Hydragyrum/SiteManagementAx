package main

import (
	"encoding/json"
	"fmt"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2"
)

type Teamserver interface {
	TsServiceSendDataAll(service string, data string)
	TsServiceSendDataClient(operator string, service string, data string)

	TsExtenderDataSave(extenderName string, key string, value []byte) error
	TsExtenderDataLoad(extenderName string, key string) ([]byte, error)
	TsExtenderDataDelete(extenderName string, key string) error
	TsExtenderDataKeys(extenderName string) ([]string, error)
}

type PluginService struct{}

var (
	Ts              Teamserver
	ModuleDir       string
	SSLCert         string
	SSLKey          string
	SiteMgr         *SiteManager
	TokenEncKeyPass string
)

func InitPlugin(ts any, moduleDir string, serviceConfig string) adaptix.PluginService {
	Ts = ts.(Teamserver)
	ModuleDir = moduleDir

	for _, line := range strings.Split(serviceConfig, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "ssl_cert":
			SSLCert = value
		case "ssl_key":
			SSLKey = value
		case "token_enc_key":
			TokenEncKeyPass = value
		}
	}

	SiteMgr = NewSiteManager()
	if err := SiteMgr.RestoreAll(); err != nil {
		fmt.Printf("[FileHost] WARNING: failed to restore sites: %v\n", err)
	}

	fmt.Printf("[FileHost] Initialized - %d site(s) restored, ssl_cert=%s\n", SiteMgr.Count(), SSLCert)
	return &PluginService{}
}

func (p *PluginService) Call(operator string, function string, args string) {
	switch function {
	case "host_file":
		go handleHostFile(operator, args)
	case "host_gitlab_file":
		go handleHostGitlabFile(operator, args)
	case "remove_site":
		go handleRemoveSite(operator, args)
	case "list_sites":
		go handleListSites(operator)
	case "generate_attack":
		go handleGenerateAttack(operator, args)
	case "get_gitlab_token":
		go handleGetGitlabToken(operator, args)
	case "update_gitlab_token":
		go handleUpdateGitlabToken(operator, args)
	default:
		sendError(operator, "Unknown function: "+function)
	}
}

func send(operator string, payload any) {
	j, _ := json.Marshal(payload)
	Ts.TsServiceSendDataClient(operator, "FileHost", string(j))
}

func broadcast(payload any) {
	j, _ := json.Marshal(payload)
	Ts.TsServiceSendDataAll("FileHost", string(j))
}

func sendError(operator string, msg string) {
	send(operator, map[string]string{"action": "error", "message": msg})
}
