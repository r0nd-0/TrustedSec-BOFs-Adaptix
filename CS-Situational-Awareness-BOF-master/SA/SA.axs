var metadata = {
    name: "CS-Situational-Awareness-BOF",
    description: "Situational Awareness BOF collection — network, host, AD, and registry enumeration"
};

// ---------------------------------------------------------------------------
// Lookup tables (converted from Sleep hashes)
// ---------------------------------------------------------------------------
var recordMapping = {
    "A": 1, "NS": 2, "MD": 3, "MF": 4, "CNAME": 5, "SOA": 6, "MB": 7,
    "MG": 8, "MR": 9, "WKS": 0xb, "PTR": 0xc, "HINFO": 0xd, "MINFO": 0xe,
    "MX": 0xf, "TEXT": 0x10, "RP": 0x11, "AFSDB": 0x12, "X25": 0x13,
    "ISDN": 0x14, "RT": 0x15, "AAAA": 0x1c, "SRV": 0x21, "WINSR": 0xff02,
    "KEY": 0x0019, "ANY": 0xff
};

var enumType = { "all": 1, "locked": 2, "disabled": 3, "active": 4 };

var regHives = { "HKCR": 0, "HKCU": 1, "HKLM": 2, "HKU": 3, "HKCU_LOCAL_IMP": 4 };

var regTypes = {
    "REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3,
    "REG_DWORD": 4, "REG_MULTI_SZ": 7, "REG_QWORD": 11
};

// ---------------------------------------------------------------------------
// Helper: build BOF path
// ---------------------------------------------------------------------------
function bofPath(agentId, name) {
    return ax.script_dir() + name + "/" + name + "." + ax.arch(agentId) + ".o";
}

// =========================================================================
//  DIRECTORY / FILE COMMANDS
// =========================================================================

var cmd_dir = ax.create_command("dir", "List a target directory using BOF", "dir [directory] [/s]", "Task: list directory");
cmd_dir.addArgString("directory", false, "Target directory (default: .\\)");
cmd_dir.addArgBool("-s", "Recurse subdirectories");
cmd_dir.setPreHook(function(agentId, cmdline, p) {
    var targetdir = p["directory"] ? p["directory"] : ".\\";
    var subdirs = p["-s"] ? 1 : 0;
    var args = ax.bof_pack("cstr,short", [targetdir, subdirs]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "dir") + " " + args);
});

var cmd_cat = ax.create_command("cat", "Print contents of a text file", "cat <filepath>", "Task: read file");
cmd_cat.addArgString("filepath", true, "File path to read");
cmd_cat.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr", [p["filepath"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "cat") + " " + args);
});

var cmd_cacls = ax.create_command("cacls", "List file permissions", "cacls <filepath>", "Task: list file ACLs");
cmd_cacls.addArgString("filepath", true, "File path (wildcards supported)");
cmd_cacls.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr", [p["filepath"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "cacls") + " " + args);
});

var cmd_md5 = ax.create_command("md5", "MD5 hash of a file", "md5 <filename>", "Task: MD5 hash");
cmd_md5.addArgString("filename", true, "File to hash");
cmd_md5.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr", [p["filename"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "md5") + " " + args);
});

var cmd_sha1 = ax.create_command("sha1", "SHA1 hash of a file", "sha1 <filename>", "Task: SHA1 hash");
cmd_sha1.addArgString("filename", true, "File to hash");
cmd_sha1.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr", [p["filename"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sha1") + " " + args);
});

var cmd_sha256 = ax.create_command("sha256", "SHA-256 hash of a file", "sha256 <filename>", "Task: SHA-256 hash");
cmd_sha256.addArgString("filename", true, "File to hash");
cmd_sha256.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr", [p["filename"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sha256") + " " + args);
});

var cmd_sha512 = ax.create_command("sha512", "SHA-512 hash of a file", "sha512 <filename>", "Task: SHA-512 hash");
cmd_sha512.addArgString("filename", true, "File to hash");
cmd_sha512.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr", [p["filename"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sha512") + " " + args);
});

var cmd_vol = ax.create_command("vol", "Display volume label and serial number", "vol [drive]", "Task: volume info");
cmd_vol.addArgString("drive", false, "Drive letter (default: CWD drive)");
cmd_vol.setPreHook(function(agentId, cmdline, p) {
    var drive = p["drive"] ? p["drive"] : "";
    var args = ax.bof_pack("cstr", [drive]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "vol") + " " + args);
});

// =========================================================================
//  NETWORK COMMANDS
// =========================================================================

var cmd_ipconfig = ax.create_command("ipconfig", "Internal ipconfig", "ipconfig", "Task: list network adapters");
cmd_ipconfig.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "ipconfig"));
});

var cmd_arp = ax.create_command("arp", "Internal ARP table", "arp", "Task: list ARP table");
cmd_arp.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "arp"));
});

var cmd_routeprint = ax.create_command("routeprint", "Print IPv4 routes", "routeprint", "Task: list routes");
cmd_routeprint.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "routeprint"));
});

var cmd_listdns = ax.create_command("listdns", "List DNS cache entries", "listdns", "Task: list DNS cache");
cmd_listdns.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "listdns"));
});

var cmd_nslookup = ax.create_command("nslookup", "Perform internal DNS query", "nslookup <lookup> [server] [type]", "Task: DNS lookup");
cmd_nslookup.addArgString("lookup", true, "IP or hostname to query");
cmd_nslookup.addArgString("server", false, "DNS server (blank for system default)");
cmd_nslookup.addArgString("type", false, "Record type (A, AAAA, CNAME, MX, SRV, etc.)");
cmd_nslookup.setPreHook(function(agentId, cmdline, p) {
    var lookup = p["lookup"];
    var server = p["server"] ? p["server"] : "";
    if (server === "127.0.0.1") {
        ax.console_message(agentId, 6, "Localhost DNS queries have a potential to crash, refusing");
        return;
    }
    if (ax.arch(agentId) === "x86" && server !== "") {
        ax.console_message(agentId, 5, "x86 beacons do not support custom DNS nameservers, overriding to default");
        server = "";
    }
    var typeStr = p["type"] ? p["type"].toUpperCase() : "A";
    var typeVal = recordMapping[typeStr] !== undefined ? recordMapping[typeStr] : recordMapping["A"];
    var args = ax.bof_pack("cstr,cstr,short", [lookup, server, typeVal]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "nslookup") + " " + args);
});

var cmd_netstat = ax.create_command("netstat", "Show local TCP/UDP ports", "netstat [ipv4] [ipv6] [tcp] [udp]", "Task: list ports");
cmd_netstat.addArgBool("-ipv4", "Show IPv4");
cmd_netstat.addArgBool("-ipv6", "Show IPv6");
cmd_netstat.addArgBool("-tcp", "Show TCP");
cmd_netstat.addArgBool("-udp", "Show UDP");
cmd_netstat.setPreHook(function(agentId, cmdline, p) {
    var hasV4 = p["-ipv4"] ? true : false;
    var hasV6 = p["-ipv6"] ? true : false;
    var hasTcp = p["-tcp"] ? true : false;
    var hasUdp = p["-udp"] ? true : false;
    if (!hasV4 && !hasV6 && !hasTcp && !hasUdp) {
        hasV4 = true; hasV6 = true; hasTcp = true; hasUdp = true;
    }
    if (!hasV4 && !hasV6) { hasV4 = true; hasV6 = true; }
    if (!hasTcp && !hasUdp) { hasTcp = true; hasUdp = true; }
    var mask = 0;
    if (hasV4 && hasTcp) mask = mask | 0x0001;
    if (hasV6 && hasTcp) mask = mask | 0x0010;
    if (hasV4 && hasUdp) mask = mask | 0x0100;
    if (hasV6 && hasUdp) mask = mask | 0x1000;
    var args = ax.bof_pack("int", [mask]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netstat") + " " + args);
});

var cmd_probe = ax.create_command("probe", "Check if a port is open", "probe <host> <port> [timeout]", "Task: port probe");
cmd_probe.addArgString("host", true, "Target host");
cmd_probe.addArgInt("port", true, "Port number");
cmd_probe.addArgInt("timeout", false, "Timeout in seconds (default: 5)");
cmd_probe.setPreHook(function(agentId, cmdline, p) {
    var port = p["port"];
    if (port < 1 || port > 65535) {
        ax.console_message(agentId, 6, "Port out of range (1-65535)");
        return;
    }
    var timeout = p["timeout"] ? p["timeout"] : 5;
    var args = ax.bof_pack("cstr,int,int", [p["host"], port, timeout]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "probe") + " " + args);
});

var cmd_listpipes = ax.create_command("listpipes", "List local named pipes", "listpipes", "Task: list named pipes");
cmd_listpipes.setPreHook(function(agentId, cmdline, p) {
    ax.execute_command(agentId, "ls //./pipe/");
});

var cmd_list_firewall_rules = ax.create_command("list_firewall_rules", "List all Windows firewall rules", "list_firewall_rules", "Task: list firewall rules");
cmd_list_firewall_rules.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "list_firewall_rules"));
});

// =========================================================================
//  HOST ENUMERATION
// =========================================================================

var cmd_env = ax.create_command("env", "Print environment variables", "env", "Task: list environment");
cmd_env.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "env"));
});

var cmd_whoami = ax.create_command("whoami", "Internal whoami /all", "whoami", "Task: whoami");
cmd_whoami.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "whoami"));
});

var cmd_hostname = ax.create_command("hostname", "Get hostname and FQDN", "hostname", "Task: hostname");
cmd_hostname.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "hostname"));
});

var cmd_locale = ax.create_command("locale", "System locale information", "locale", "Task: locale info");
cmd_locale.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "locale"));
});

var cmd_uptime = ax.create_command("uptime", "System boot time", "uptime", "Task: uptime");
cmd_uptime.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "uptime"));
});

var cmd_resources = ax.create_command("resources", "Available memory and disk space", "resources", "Task: system resources");
cmd_resources.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "resources"));
});

var cmd_useridletime = ax.create_command("useridletime", "User idle time", "useridletime", "Task: idle time");
cmd_useridletime.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "useridletime"));
});

var cmd_windowlist = ax.create_command("windowlist", "List visible windows", "windowlist [all]", "Task: list windows");
cmd_windowlist.addArgString("mode", false, "Pass 'all' to see every window");
cmd_windowlist.setPreHook(function(agentId, cmdline, p) {
    var showAll = (p["mode"] === "all") ? 1 : 0;
    var args = ax.bof_pack("int", [showAll]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "windowlist") + " " + args);
});

var cmd_notepad = ax.create_command("notepad", "Grab text from open notepad windows", "notepad", "Task: read notepad");
cmd_notepad.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "notepad"));
});

var cmd_driversigs = ax.create_command("driversigs", "Check drivers for known EDR vendors", "driversigs", "Task: EDR driver check");
cmd_driversigs.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "driversigs"));
});

var cmd_enum_filter_driver = ax.create_command("enum_filter_driver", "List filter drivers", "enum_filter_driver [system]", "Task: list filter drivers");
cmd_enum_filter_driver.addArgString("system", false, "Remote system (local if omitted)");
cmd_enum_filter_driver.setPreHook(function(agentId, cmdline, p) {
    var system = p["system"] ? p["system"] : null;
    var args = ax.bof_pack("cstr", [system]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "enum_filter_driver") + " " + args);
});

var cmd_adv_audit_policies = ax.create_command("adv_audit_policies", "Retrieve advanced security audit policies", "adv_audit_policies", "Task: audit policies");
cmd_adv_audit_policies.setPreHook(function(agentId, cmdline, p) {
    var iswow64 = (ax.is64(agentId) && ax.arch(agentId) === "x86") ? 1 : 0;
    var args = ax.bof_pack("int", [iswow64]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "adv_audit_policies") + " " + args);
});

var cmd_listmods = ax.create_command("listmods", "List process modules", "listmods [pid]", "Task: list modules");
cmd_listmods.addArgInt("pid", false, "Process ID (0 = current process)");
cmd_listmods.setPreHook(function(agentId, cmdline, p) {
    var pid = p["pid"] ? p["pid"] : 0;
    var args = ax.bof_pack("int", [pid]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "listmods") + " " + args);
});

var cmd_findLoadedModule = ax.create_command("findLoadedModule", "Find processes loading a specific DLL", "findLoadedModule <dllname> [procname]", "Task: find loaded module");
cmd_findLoadedModule.addArgString("dllname", true, "Partial DLL name to search");
cmd_findLoadedModule.addArgString("procname", false, "Partial process name filter");
cmd_findLoadedModule.setPreHook(function(agentId, cmdline, p) {
    if (ax.is64(agentId) && ax.arch(agentId) === "x86") {
        ax.console_message(agentId, 6, "Unable to run under WOW64 (32bit proc on 64bit host)");
        return;
    }
    var procname = p["procname"] ? p["procname"] : "";
    var args = ax.bof_pack("cstr,cstr", [p["dllname"], procname]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "findLoadedModule") + " " + args);
});

var cmd_enumLocalSessions = ax.create_command("enumLocalSessions", "Enumerate attached user sessions", "enumLocalSessions", "Task: enum sessions");
cmd_enumLocalSessions.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "enumlocalsessions"));
});

var cmd_get_dpapi_system = ax.create_command("get_dpapi_system", "Print DPAPI_SYSTEM and boot key", "get_dpapi_system", "Task: DPAPI system key");
cmd_get_dpapi_system.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "get_dpapi_system"));
});

var cmd_get_session_info = ax.create_command("get_session_info", "Auth package, logon server, session ID", "get_session_info", "Task: session info");
cmd_get_session_info.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "get_session_info"));
});

var cmd_aadjoininfo = ax.create_command("aadjoininfo", "Azure AD/Entra ID join information", "aadjoininfo", "Task: AAD join info");
cmd_aadjoininfo.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "aadjoininfo"));
});

// =========================================================================
//  NETWORK ENUMERATION (Remote)
// =========================================================================

var cmd_netview = ax.create_command("netview", "List workstations and servers", "netview [domain]", "Task: netview");
cmd_netview.addArgString("domain", false, "NetBIOS domain name");
cmd_netview.setPreHook(function(agentId, cmdline, p) {
    var domain = p["domain"] ? p["domain"] : "";
    var args = ax.bof_pack("cstr", [domain]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netview") + " " + args);
});

var cmd_netsession = ax.create_command("netsession", "List sessions on server", "netsession <computer>", "Task: net sessions");
cmd_netsession.addArgString("computer", false, "Target computer");
cmd_netsession.setPreHook(function(agentId, cmdline, p) {
    var computer = p["computer"] ? p["computer"] : "";
    var args = ax.bof_pack("cstr", [computer]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "get-netsession") + " " + args);
});

var cmd_netsession2 = ax.create_command("netsession2", "List sessions (bofhound compatible)", "netsession2 [computer] [method] [dns_server]", "Task: net sessions v2");
cmd_netsession2.addArgString("computer", false, "Target computer");
cmd_netsession2.addArgInt("method", false, "Resolution method (1=DNS, 2=NetWkstaGetInfo)");
cmd_netsession2.addArgString("dns_server", false, "DNS server for resolution");
cmd_netsession2.setPreHook(function(agentId, cmdline, p) {
    var hostname = p["computer"] ? p["computer"] : "";
    var method = p["method"] ? p["method"] : 1;
    var dnsserver = p["dns_server"] ? p["dns_server"] : "";
    var args = ax.bof_pack("cstr,short,cstr", [hostname, method, dnsserver]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "get-netsession2") + " " + args);
});

var cmd_netloggedon = ax.create_command("netloggedon", "Users logged on (admin required)", "netloggedon [computer]", "Task: logged on users");
cmd_netloggedon.addArgString("computer", false, "Target computer");
cmd_netloggedon.setPreHook(function(agentId, cmdline, p) {
    var name = p["computer"] ? p["computer"] : "";
    var args = ax.bof_pack("cstr,int", [name, 0]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netloggedon") + " " + args);
});

var cmd_netloggedon2 = ax.create_command("netloggedon2", "Users logged on via NetWkstaUserEnum (bofhound compatible)", "netloggedon2 [computer]", "Task: logged on v2");
cmd_netloggedon2.addArgString("computer", false, "Target computer");
cmd_netloggedon2.setPreHook(function(agentId, cmdline, p) {
    var name = p["computer"] ? p["computer"] : "";
    var args = ax.bof_pack("cstr,int", [name, 0]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netloggedon2") + " " + args);
});

var cmd_netuptime = ax.create_command("netuptime", "Remote machine boot time", "netuptime [computer]", "Task: remote uptime");
cmd_netuptime.addArgString("computer", false, "Target computer");
cmd_netuptime.setPreHook(function(agentId, cmdline, p) {
    var name = p["computer"] ? p["computer"] : "";
    var args = ax.bof_pack("cstr,int", [name, 0]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netuptime") + " " + args);
});

var cmd_nettime = ax.create_command("nettime", "Current time on remote machine", "nettime [computer]", "Task: remote time");
cmd_nettime.addArgString("computer", false, "Target computer");
cmd_nettime.setPreHook(function(agentId, cmdline, p) {
    var name = p["computer"] ? p["computer"] : "";
    var args = ax.bof_pack("cstr", [name]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "nettime") + " " + args);
});

var cmd_netshares = ax.create_command("netshares", "List shares on computer", "netshares [computer]", "Task: list shares");
cmd_netshares.addArgString("computer", false, "Target computer");
cmd_netshares.setPreHook(function(agentId, cmdline, p) {
    var name = p["computer"] ? p["computer"] : "";
    var args = ax.bof_pack("cstr,int", [name, 0]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netshares") + " " + args);
});

var cmd_netsharesAdmin = ax.create_command("netsharesAdmin", "List shares with admin detail", "netsharesAdmin [computer]", "Task: admin shares");
cmd_netsharesAdmin.addArgString("computer", false, "Target computer");
cmd_netsharesAdmin.setPreHook(function(agentId, cmdline, p) {
    var name = p["computer"] ? p["computer"] : "";
    var args = ax.bof_pack("cstr,int", [name, 1]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netshares") + " " + args);
});

var cmd_regsession = ax.create_command("regsession", "Logged-on users via registry (bofhound compatible)", "regsession [computer]", "Task: reg sessions");
cmd_regsession.addArgString("computer", false, "Target computer");
cmd_regsession.setPreHook(function(agentId, cmdline, p) {
    var name = p["computer"] ? p["computer"] : "";
    var args = ax.bof_pack("cstr", [name]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "regsession") + " " + args);
});

// =========================================================================
//  NET USE COMMANDS
// =========================================================================

var cmd_netuse_add = ax.create_command("netuse_add", "Connect to a shared resource", "netuse_add <share> <user> <password> [/DEVICE:X] [/PERSIST] [/REQUIREPRIVACY]", "Task: net use add");
cmd_netuse_add.addArgString("share", true, "Network share path");
cmd_netuse_add.addArgString("user", true, "Username (\"\" for current)");
cmd_netuse_add.addArgString("password", true, "Password (\"\" for current)");
cmd_netuse_add.addArgFlagString("-DEVICE", "device", false, "Local device name (e.g. Y)");
cmd_netuse_add.addArgBool("-PERSIST", "Persist the connection");
cmd_netuse_add.addArgBool("-REQUIREPRIVACY", "Require SMBv3 encryption");
cmd_netuse_add.setPreHook(function(agentId, cmdline, p) {
    var device = p["device"] ? p["device"] + ":" : "";
    var persist = p["-PERSIST"] ? 1 : 0;
    var reqencrypt = p["-REQUIREPRIVACY"] ? 1 : 0;
    var args = ax.bof_pack("short,cstr,cstr,cstr,cstr,short,short", [1, p["share"], p["user"], p["password"], device, persist, reqencrypt]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netuse") + " " + args);
});

var cmd_netuse_list = ax.create_command("netuse_list", "List bound connections", "netuse_list [device|share]", "Task: net use list");
cmd_netuse_list.addArgString("target", false, "Device letter or remote share");
cmd_netuse_list.setPreHook(function(agentId, cmdline, p) {
    var target = "";
    if (p["target"]) {
        target = p["target"];
        if (target.length === 1) target = target + ":";
        if (target.length > 2 && target.substring(0, 2) !== "\\\\") target = "\\\\" + target;
    }
    var args = ax.bof_pack("short,cstr", [2, target]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netuse") + " " + args);
});

var cmd_netuse_delete = ax.create_command("netuse_delete", "Disconnect from a shared resource", "netuse_delete <device|share> [/PERSIST] [/FORCE]", "Task: net use delete");
cmd_netuse_delete.addArgString("target", true, "Device name or share path");
cmd_netuse_delete.addArgBool("-PERSIST", "Delete persistent mapping");
cmd_netuse_delete.addArgBool("-FORCE", "Force disconnect even if resources open");
cmd_netuse_delete.setPreHook(function(agentId, cmdline, p) {
    var target = p["target"];
    if (target.length === 1) target = target + ":";
    if (target.length > 2 && target.substring(0, 2) !== "\\\\") target = "\\\\" + target;
    var persist = p["-PERSIST"] ? 1 : 0;
    var force = p["-FORCE"] ? 1 : 0;
    var args = ax.bof_pack("short,cstr,short,short", [3, target, persist, force]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netuse") + " " + args);
});

// =========================================================================
//  USER / GROUP ENUMERATION
// =========================================================================

var cmd_netuser = ax.create_command("netuser", "User account info", "netuser <username> [domain]", "Task: net user");
cmd_netuser.addArgString("username", true, "Username to query");
cmd_netuser.addArgString("domain", false, "DNS or NetBIOS domain (local if omitted)");
cmd_netuser.setPreHook(function(agentId, cmdline, p) {
    var domain = p["domain"] ? p["domain"] : "";
    var args = ax.bof_pack("cstr,cstr", [p["username"], domain]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netuser") + " " + args);
});

var cmd_userenum = ax.create_command("userenum", "List local user accounts", "userenum [all|locked|disabled|active]", "Task: enum local users");
cmd_userenum.addArgString("filter", false, "Filter: all, locked, disabled, active");
cmd_userenum.setPreHook(function(agentId, cmdline, p) {
    var filterStr = p["filter"] ? p["filter"] : "all";
    var type = enumType[filterStr];
    if (type === undefined) {
        ax.console_message(agentId, 6, "Invalid filter. Use: all, locked, disabled, active");
        return;
    }
    var args = ax.bof_pack("int,int", [0, type]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netuserenum") + " " + args);
});

var cmd_domainenum = ax.create_command("domainenum", "List domain user accounts", "domainenum [all|locked|disabled|active]", "Task: enum domain users");
cmd_domainenum.addArgString("filter", false, "Filter: all, locked, disabled, active");
cmd_domainenum.setPreHook(function(agentId, cmdline, p) {
    var filterStr = p["filter"] ? p["filter"] : "all";
    var type = enumType[filterStr];
    if (type === undefined) {
        ax.console_message(agentId, 6, "Invalid filter. Use: all, locked, disabled, active");
        return;
    }
    var args = ax.bof_pack("int,int", [1, type]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netuserenum") + " " + args);
});

var cmd_netGroupList = ax.create_command("netGroupList", "List domain groups", "netGroupList [domain]", "Task: list domain groups");
cmd_netGroupList.addArgString("domain", false, "Domain name");
cmd_netGroupList.setPreHook(function(agentId, cmdline, p) {
    var domain = p["domain"] ? p["domain"] : "";
    var args = ax.bof_pack("short,cstr,cstr", [0, domain, ""]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netgroup") + " " + args);
});

var cmd_netGroupListMembers = ax.create_command("netGroupListMembers", "List members of a domain group", "netGroupListMembers <group> [domain]", "Task: group members");
cmd_netGroupListMembers.addArgString("group", true, "Group name");
cmd_netGroupListMembers.addArgString("domain", false, "Domain name");
cmd_netGroupListMembers.setPreHook(function(agentId, cmdline, p) {
    var domain = p["domain"] ? p["domain"] : "";
    var args = ax.bof_pack("short,cstr,cstr", [1, domain, p["group"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netgroup") + " " + args);
});

var cmd_netLocalGroupList = ax.create_command("netLocalGroupList", "List local groups", "netLocalGroupList [server]", "Task: list local groups");
cmd_netLocalGroupList.addArgString("server", false, "Server name");
cmd_netLocalGroupList.setPreHook(function(agentId, cmdline, p) {
    var server = p["server"] ? p["server"] : "";
    var args = ax.bof_pack("short,cstr,cstr", [0, server, ""]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netlocalgroup") + " " + args);
});

var cmd_netLocalGroupListMembers = ax.create_command("netLocalGroupListMembers", "List members of a local group", "netLocalGroupListMembers <group> [server]", "Task: local group members");
cmd_netLocalGroupListMembers.addArgString("group", true, "Group name");
cmd_netLocalGroupListMembers.addArgString("server", false, "Server name");
cmd_netLocalGroupListMembers.setPreHook(function(agentId, cmdline, p) {
    var server = p["server"] ? p["server"] : "";
    var args = ax.bof_pack("short,cstr,cstr", [1, server, p["group"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netlocalgroup") + " " + args);
});

var cmd_netLocalGroupListMembers2 = ax.create_command("netLocalGroupListMembers2", "Local group members (bofhound compatible)", "netLocalGroupListMembers2 [group] [server]", "Task: local group members v2");
cmd_netLocalGroupListMembers2.addArgString("group", false, "Group name (\"\" for all interesting groups)");
cmd_netLocalGroupListMembers2.addArgString("server", false, "Server name");
cmd_netLocalGroupListMembers2.setPreHook(function(agentId, cmdline, p) {
    var group = p["group"] ? p["group"] : "";
    var server = p["server"] ? p["server"] : "";
    var args = ax.bof_pack("cstr,cstr", [server, group]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "netlocalgroup2") + " " + args);
});

var cmd_get_password_policy = ax.create_command("get_password_policy", "Server/DC password policy", "get_password_policy <server>", "Task: password policy");
cmd_get_password_policy.addArgString("server", true, "Target server or DC");
cmd_get_password_policy.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr", [p["server"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "get_password_policy") + " " + args);
});

// =========================================================================
//  LDAP
// =========================================================================

var cmd_ldapsearch = ax.create_command("ldapsearch", "Perform LDAP search", "ldapsearch <query> [--attributes a] [--count n] [--scope s] [--hostname h] [--dn d] [--ldaps]", "Task: LDAP search");
cmd_ldapsearch.addArgString("query", true, "LDAP query string");
cmd_ldapsearch.addArgFlagString("--attributes", "attributes", false, "Comma-separated attributes (default: *)");
cmd_ldapsearch.addArgFlagInt("--count", "count", false, "Max results (default: 0 = unlimited)");
cmd_ldapsearch.addArgFlagInt("--scope", "scope", false, "Scope: 1=BASE, 2=LEVEL, 3=SUBTREE (default: 3)");
cmd_ldapsearch.addArgFlagString("--hostname", "hostname", false, "DC hostname or IP");
cmd_ldapsearch.addArgFlagString("--dn", "dn", false, "LDAP query base DN");
cmd_ldapsearch.addArgBool("--ldaps", "Use LDAPS");
cmd_ldapsearch.setPreHook(function(agentId, cmdline, p) {
    var query = p["query"];
    var attributes = p["attributes"] ? p["attributes"] : "*";
    var result_limit = p["count"] ? p["count"] : 0;
    var scope = p["scope"] ? p["scope"] : 3;
    var hostname = p["hostname"] ? p["hostname"] : "";
    var dn = p["dn"] ? p["dn"] : "";
    var ldaps = p["--ldaps"] ? 1 : 0;
    var args = ax.bof_pack("cstr,cstr,int,int,cstr,cstr,int", [query, attributes, result_limit, scope, hostname, dn, ldaps]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "ldapsearch") + " " + args);
});

var cmd_nonpagedldapsearch = ax.create_command("nonpagedldapsearch", "Non-paged LDAP search", "nonpagedldapsearch <query> [attributes] [count] [hostname] [domain]", "Task: LDAP search (non-paged)");
cmd_nonpagedldapsearch.addArgString("query", true, "LDAP query");
cmd_nonpagedldapsearch.addArgString("attributes", false, "Attributes (default: empty)");
cmd_nonpagedldapsearch.addArgInt("count", false, "Max results (default: 0)");
cmd_nonpagedldapsearch.addArgString("hostname", false, "DC hostname");
cmd_nonpagedldapsearch.addArgString("domain", false, "Domain");
cmd_nonpagedldapsearch.setPreHook(function(agentId, cmdline, p) {
    var attributes = p["attributes"] ? p["attributes"] : "";
    var result_limit = p["count"] ? p["count"] : 0;
    var hostname = p["hostname"] ? p["hostname"] : "";
    var domain = p["domain"] ? p["domain"] : "";
    var args = ax.bof_pack("cstr,cstr,int,cstr,cstr", [p["query"], attributes, result_limit, hostname, domain]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "nonpagedldapsearch") + " " + args);
});

var cmd_ldapsecuritycheck = ax.create_command("ldapsecuritycheck", "Check LDAP signing and channel binding", "ldapsecuritycheck [dc]", "Task: LDAP security check");
cmd_ldapsecuritycheck.addArgString("dc", false, "Domain Controller hostname or IP");
cmd_ldapsecuritycheck.setPreHook(function(agentId, cmdline, p) {
    var dc = p["dc"] ? p["dc"] : "";
    var args = ax.bof_pack("cstr", [dc]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "ldapsecuritycheck") + " " + args);
});

// =========================================================================
//  ADCS
// =========================================================================

var cmd_adcs_enum = ax.create_command("adcs_enum", "Enumerate CAs and templates (Win32)", "adcs_enum [domain]", "Task: ADCS enum");
cmd_adcs_enum.addArgString("domain", false, "Target domain");
cmd_adcs_enum.setPreHook(function(agentId, cmdline, p) {
    var domain = p["domain"] ? p["domain"] : "";
    var args = ax.bof_pack("cstr", [domain]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "adcs_enum") + " " + args);
});

var cmd_adcs_enum_com = ax.create_command("adcs_enum_com", "Enumerate CAs and templates (ICertConfig COM)", "adcs_enum_com", "Task: ADCS enum COM");
cmd_adcs_enum_com.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "adcs_enum_com"));
});

var cmd_adcs_enum_com2 = ax.create_command("adcs_enum_com2", "Enumerate CAs and templates (IX509 COM)", "adcs_enum_com2", "Task: ADCS enum COM2");
cmd_adcs_enum_com2.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "adcs_enum_com2"));
});

// =========================================================================
//  ACTIVE DIRECTORY RECYCLE BIN
// =========================================================================

var cmd_adrbstatus = ax.create_command("adrbstatus", "Check if AD Recycling Bin is enabled", "adrbstatus", "Task: ADRB status");
cmd_adrbstatus.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "adrbstatus"));
});

var cmd_adrbperms = ax.create_command("adrbperms", "Check read access to AD Recycling Bin", "adrbperms", "Task: ADRB perms");
cmd_adrbperms.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "adrbperms"));
});

var cmd_adrblist = ax.create_command("adrblist", "List deleted objects in AD Recycling Bin", "adrblist", "Task: ADRB list");
cmd_adrblist.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "adrblist"));
});

// =========================================================================
//  SERVICE CONTROL QUERIES
// =========================================================================

var cmd_sc_query = ax.create_command("sc_query", "Query service status", "sc_query [service] [hostname]", "Task: sc query");
cmd_sc_query.addArgString("service", false, "Service name (all if omitted)");
cmd_sc_query.addArgString("hostname", false, "Remote host");
cmd_sc_query.setPreHook(function(agentId, cmdline, p) {
    var hostname = p["hostname"] ? p["hostname"] : null;
    var servicename = p["service"] ? p["service"] : null;
    var args = ax.bof_pack("cstr,cstr", [hostname, servicename]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_query") + " " + args);
});

var cmd_sc_qc = ax.create_command("sc_qc", "Query service configuration", "sc_qc <service> [hostname]", "Task: sc qc");
cmd_sc_qc.addArgString("service", true, "Service name");
cmd_sc_qc.addArgString("hostname", false, "Remote host");
cmd_sc_qc.setPreHook(function(agentId, cmdline, p) {
    var hostname = p["hostname"] ? p["hostname"] : null;
    var args = ax.bof_pack("cstr,cstr", [hostname, p["service"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_qc") + " " + args);
});

var cmd_sc_qdescription = ax.create_command("sc_qdescription", "Query service description", "sc_qdescription <service> [hostname]", "Task: sc qdescription");
cmd_sc_qdescription.addArgString("service", true, "Service name");
cmd_sc_qdescription.addArgString("hostname", false, "Remote host");
cmd_sc_qdescription.setPreHook(function(agentId, cmdline, p) {
    var hostname = p["hostname"] ? p["hostname"] : null;
    var args = ax.bof_pack("cstr,cstr", [hostname, p["service"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_qdescription") + " " + args);
});

var cmd_sc_qfailure = ax.create_command("sc_qfailure", "List service failure actions", "sc_qfailure <service> [hostname]", "Task: sc qfailure");
cmd_sc_qfailure.addArgString("service", true, "Service name");
cmd_sc_qfailure.addArgString("hostname", false, "Remote host");
cmd_sc_qfailure.setPreHook(function(agentId, cmdline, p) {
    var hostname = p["hostname"] ? p["hostname"] : null;
    var args = ax.bof_pack("cstr,cstr", [hostname, p["service"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_qfailure") + " " + args);
});

var cmd_sc_qtriggerinfo = ax.create_command("sc_qtriggerinfo", "List service triggers", "sc_qtriggerinfo <service> [hostname]", "Task: sc qtriggerinfo");
cmd_sc_qtriggerinfo.addArgString("service", true, "Service name");
cmd_sc_qtriggerinfo.addArgString("hostname", false, "Remote host");
cmd_sc_qtriggerinfo.setPreHook(function(agentId, cmdline, p) {
    var hostname = p["hostname"] ? p["hostname"] : null;
    var args = ax.bof_pack("cstr,cstr", [hostname, p["service"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_qtriggerinfo") + " " + args);
});

var cmd_sc_enum = ax.create_command("sc_enum", "Enumerate all service configs", "sc_enum [hostname]", "Task: sc enum");
cmd_sc_enum.addArgString("hostname", false, "Remote host");
cmd_sc_enum.setPreHook(function(agentId, cmdline, p) {
    var hostname = p["hostname"] ? p["hostname"] : null;
    var args = ax.bof_pack("cstr", [hostname]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_enum") + " " + args);
});

// =========================================================================
//  SCHEDULED TASKS
// =========================================================================

var cmd_schtasksenum = ax.create_command("schtasksenum", "Enumerate scheduled tasks", "schtasksenum [target]", "Task: schtasks enum");
cmd_schtasksenum.addArgString("target", false, "Remote target");
cmd_schtasksenum.setPreHook(function(agentId, cmdline, p) {
    var target = p["target"] ? p["target"] : "";
    var args = ax.bof_pack("cstr", [target]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "schtasksenum") + " " + args);
});

var cmd_schtasksquery = ax.create_command("schtasksquery", "Query scheduled task details", "schtasksquery [server] <taskname>", "Task: schtasks query");
cmd_schtasksquery.addArgString("taskname", true, "Task name (full path)");
cmd_schtasksquery.addArgString("server", false, "Remote server");
cmd_schtasksquery.setPreHook(function(agentId, cmdline, p) {
    var server = p["server"] ? p["server"] : "";
    var args = ax.bof_pack("cstr,cstr", [server, p["taskname"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "schtasksquery") + " " + args);
});

// =========================================================================
//  REGISTRY
// =========================================================================

var cmd_reg_query = ax.create_command("reg_query", "Query registry key or value", "reg_query [hostname] <hive> <path> [value]", "Task: reg query");
cmd_reg_query.addArgString("hive", true, "Registry hive (HKLM, HKCU, HKU, HKCR, HKCU_LOCAL_IMP)");
cmd_reg_query.addArgString("path", true, "Registry path");
cmd_reg_query.addArgString("value", false, "Value name (enumerate key if omitted)");
cmd_reg_query.addArgString("hostname", false, "Remote host");
cmd_reg_query.setPreHook(function(agentId, cmdline, p) {
    var hiveStr = p["hive"];
    if (regHives[hiveStr] === undefined) {
        ax.console_message(agentId, 6, "Invalid hive. Use: HKLM, HKCU, HKU, HKCR, HKCU_LOCAL_IMP");
        return;
    }
    var hostname = p["hostname"] ? "\\\\" + p["hostname"] : null;
    var key = p["value"] ? p["value"] : "";
    var args = ax.bof_pack("cstr,int,cstr,cstr,int", [hostname, regHives[hiveStr], p["path"], key, 0]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "reg_query") + " " + args);
});

var cmd_reg_query_recursive = ax.create_command("reg_query_recursive", "Recursively query registry key", "reg_query_recursive [hostname] <hive> <path>", "Task: reg query recursive");
cmd_reg_query_recursive.addArgString("hive", true, "Registry hive");
cmd_reg_query_recursive.addArgString("path", true, "Registry path");
cmd_reg_query_recursive.addArgString("hostname", false, "Remote host");
cmd_reg_query_recursive.setPreHook(function(agentId, cmdline, p) {
    var hiveStr = p["hive"];
    if (regHives[hiveStr] === undefined) {
        ax.console_message(agentId, 6, "Invalid hive. Use: HKLM, HKCU, HKU, HKCR, HKCU_LOCAL_IMP");
        return;
    }
    var hostname = p["hostname"] ? "\\\\" + p["hostname"] : null;
    var args = ax.bof_pack("cstr,int,cstr,cstr,int", [hostname, regHives[hiveStr], p["path"], "", 1]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "reg_query") + " " + args);
});

// =========================================================================
//  WMI
// =========================================================================

var cmd_tasklist = ax.create_command("tasklist", "List running processes via WMI", "tasklist [system]", "Task: process list");
cmd_tasklist.addArgString("system", false, "Remote system");
cmd_tasklist.setPreHook(function(agentId, cmdline, p) {
    var resource = p["system"] ? "\\\\" + p["system"] + "\\root\\cimv2" : "\\\\.\\root\\cimv2";
    var args = ax.bof_pack("cstr", [resource]);
    ax.console_message(agentId, 5, "Connecting to " + resource);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "tasklist") + " " + args);
});

var cmd_wmi_query = ax.create_command("wmi_query", "Run a general WMI query", "wmi_query <query> [system] [namespace]", "Task: WMI query");
cmd_wmi_query.addArgString("query", true, "WQL query");
cmd_wmi_query.addArgString("system", false, "Remote system (default: local)");
cmd_wmi_query.addArgString("namespace", false, "WMI namespace (default: root\\cimv2)");
cmd_wmi_query.setPreHook(function(agentId, cmdline, p) {
    var system = p["system"] ? p["system"] : ".";
    var ns = p["namespace"] ? p["namespace"] : "root\\cimv2";
    var resource = "\\\\" + system + "\\" + ns;
    var args = ax.bof_pack("cstr,cstr,cstr,cstr", [system, ns, p["query"], resource]);
    ax.console_message(agentId, 5, "Connecting to " + resource + " — " + p["query"]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "wmi_query") + " " + args);
});

// =========================================================================
//  VSS
// =========================================================================

var cmd_vssenum = ax.create_command("vssenum", "Enumerate volume snapshots", "vssenum <hostname> [sharename]", "Task: VSS enum");
cmd_vssenum.addArgString("hostname", true, "Target hostname");
cmd_vssenum.addArgString("sharename", false, "Share name (default: C$)");
cmd_vssenum.setPreHook(function(agentId, cmdline, p) {
    var sharename = p["sharename"] ? p["sharename"] : "C$";
    var args = ax.bof_pack("cstr,cstr", [p["hostname"], sharename]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "vssenum") + " " + args);
});

// =========================================================================
//  REGISTER COMMAND GROUPS
// =========================================================================

var grpFiles = ax.create_commands_group("SA — File Operations", [
    cmd_dir, cmd_cat, cmd_cacls, cmd_md5, cmd_sha1, cmd_sha256, cmd_sha512, cmd_vol
]);

var grpNetwork = ax.create_commands_group("SA — Network", [
    cmd_ipconfig, cmd_arp, cmd_routeprint, cmd_listdns, cmd_nslookup,
    cmd_netstat, cmd_probe, cmd_listpipes, cmd_list_firewall_rules
]);

var grpHost = ax.create_commands_group("SA — Host Enumeration", [
    cmd_env, cmd_whoami, cmd_hostname, cmd_locale, cmd_uptime, cmd_resources,
    cmd_useridletime, cmd_windowlist, cmd_notepad, cmd_driversigs,
    cmd_enum_filter_driver, cmd_adv_audit_policies, cmd_listmods,
    cmd_findLoadedModule, cmd_enumLocalSessions, cmd_get_dpapi_system,
    cmd_get_session_info, cmd_aadjoininfo
]);

var grpRemote = ax.create_commands_group("SA — Remote Enumeration", [
    cmd_netview, cmd_netsession, cmd_netsession2, cmd_netloggedon,
    cmd_netloggedon2, cmd_netuptime, cmd_nettime, cmd_netshares,
    cmd_netsharesAdmin, cmd_regsession
]);

var grpNetUse = ax.create_commands_group("SA — Net Use", [
    cmd_netuse_add, cmd_netuse_list, cmd_netuse_delete
]);

var grpUsers = ax.create_commands_group("SA — User & Group Enumeration", [
    cmd_netuser, cmd_userenum, cmd_domainenum, cmd_netGroupList,
    cmd_netGroupListMembers, cmd_netLocalGroupList,
    cmd_netLocalGroupListMembers, cmd_netLocalGroupListMembers2,
    cmd_get_password_policy
]);

var grpLdap = ax.create_commands_group("SA — LDAP", [
    cmd_ldapsearch, cmd_nonpagedldapsearch, cmd_ldapsecuritycheck
]);

var grpAdcs = ax.create_commands_group("SA — ADCS", [
    cmd_adcs_enum, cmd_adcs_enum_com, cmd_adcs_enum_com2
]);

var grpAdrb = ax.create_commands_group("SA — AD Recycle Bin", [
    cmd_adrbstatus, cmd_adrbperms, cmd_adrblist
]);

var grpServices = ax.create_commands_group("SA — Service Queries", [
    cmd_sc_query, cmd_sc_qc, cmd_sc_qdescription, cmd_sc_qfailure,
    cmd_sc_qtriggerinfo, cmd_sc_enum
]);

var grpTasks = ax.create_commands_group("SA — Scheduled Tasks", [
    cmd_schtasksenum, cmd_schtasksquery
]);

var grpRegistry = ax.create_commands_group("SA — Registry", [
    cmd_reg_query, cmd_reg_query_recursive
]);

var grpWmi = ax.create_commands_group("SA — WMI", [
    cmd_tasklist, cmd_wmi_query
]);

var grpVss = ax.create_commands_group("SA — VSS", [
    cmd_vssenum
]);

ax.register_commands_group(grpFiles, ["beacon"], ["windows"], []);
ax.register_commands_group(grpNetwork, ["beacon"], ["windows"], []);
ax.register_commands_group(grpHost, ["beacon"], ["windows"], []);
ax.register_commands_group(grpRemote, ["beacon"], ["windows"], []);
ax.register_commands_group(grpNetUse, ["beacon"], ["windows"], []);
ax.register_commands_group(grpUsers, ["beacon"], ["windows"], []);
ax.register_commands_group(grpLdap, ["beacon"], ["windows"], []);
ax.register_commands_group(grpAdcs, ["beacon"], ["windows"], []);
ax.register_commands_group(grpAdrb, ["beacon"], ["windows"], []);
ax.register_commands_group(grpServices, ["beacon"], ["windows"], []);
ax.register_commands_group(grpTasks, ["beacon"], ["windows"], []);
ax.register_commands_group(grpRegistry, ["beacon"], ["windows"], []);
ax.register_commands_group(grpWmi, ["beacon"], ["windows"], []);
ax.register_commands_group(grpVss, ["beacon"], ["windows"], []);
