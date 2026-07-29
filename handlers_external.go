package main

import (
	"encoding/json"
	"fmt"
)

func handleHostExternalURL(operator string, args string) {
	var req struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		sendError(operator, "Invalid args: "+err.Error())
		return
	}

	site, err := createExternalSiteFromURL(req.URL, operator)
	if err != nil {
		sendError(operator, "Failed to create external site: "+err.Error())
		return
	}

	fmt.Printf("[FileHost] Added external site: %s (%s, %d bytes) by %s\n", site.SiteKey(), site.ContentType, site.FileSize, operator)
	addHostedSite(site)
}
