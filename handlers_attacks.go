package main

import "encoding/json"

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
		"action": "attack_generated", "method": req.Method, "url": req.URL, "script": script,
	})
}
