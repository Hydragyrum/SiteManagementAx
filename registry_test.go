package main

import "testing"

func TestExtensionRegistries(t *testing.T) {
	for _, command := range []string{
		"host_file",
		"host_gitlab_file",
		"host_external_url",
		"remove_site",
		"list_sites",
		"generate_attack",
		"get_gitlab_token",
		"update_gitlab_token",
	} {
		if commandHandlers[command] == nil {
			t.Fatalf("missing command handler %q", command)
		}
	}

	for _, siteType := range []int{SiteTypeDefault, SiteTypeGitLab, SiteTypeExternal} {
		if siteProviders[siteType].remove == nil {
			t.Fatalf("missing remove handler for site type %d", siteType)
		}
	}
}
