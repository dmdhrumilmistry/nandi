# Fleets: Jamf, Intune and Linux

On a fleet of laptops each person runs their own nandi next to their own
agents. IT decides how those instances behave with **managed settings**.
These are pushed by the device management tool, merged over each user's
`nandi.yaml`, and cannot be changed by the user. Everything needed is in
[`deploy/mdm`](https://github.com/dmdhrumilmistry/nandi/tree/main/deploy/mdm)
and ships in every release archive.

| | macOS | Windows | Linux |
|---|---|---|---|
| Push settings with | a configuration profile (Jamf, Kandji, Mosyle, Intune) | the ADMX policy (Intune, Group Policy) | a file (Ansible, Puppet, Chef, Salt) |
| nandi reads | `/Library/Managed Preferences/io.github.dmdhrumilmistry.nandi.plist`, `/Library/Application Support/nandi/managed.yaml` | `HKLM\SOFTWARE\Policies\nandi` (`Config`), `%ProgramData%\nandi\managed.yaml` | `/etc/nandi/managed.yaml`, `/etc/nandi/managed.d/*.yaml` |
| Install with | `install-nandi.sh` (Jamf policy) | `Install-Nandi.ps1` (Intune Win32 app) | your package or config tool |
| Runs per user | launch agents | scheduled tasks | systemd user units |

## How managed settings apply

Managed settings use the same keys as `nandi.yaml`. Every nandi command
that loads a configuration merges them on top:

- Maps merge key by key, and lists and values replace. A managed
  `servers.on_unknown: deny` keeps the user's other `servers` settings, and
  a managed `policy.rules` list replaces the user's list.
- Later sources win: system files first, then the profile or registry
  policy.
- With managed settings the user's `nandi.yaml` may be missing. They are
  then the whole configuration.
- There is no flag or environment variable to skip them. A managed file
  that users other than its owner can write is ignored with a warning,
  because anyone could otherwise have changed it.

Check what a machine has in effect, and whether it is valid:

```text
$ nandi managed
source   /Library/Managed Preferences/io.github.dmdhrumilmistry.nandi.plist (configuration profile, key Config)
source   /Library/Managed Preferences/io.github.dmdhrumilmistry.nandi.plist (configuration profile)
result   valid together with nandi.yaml

mode: enforce
...
```

Check a file before you deploy it with `nandi managed --file managed.yaml`.
It exits non-zero and names the bad key when something is wrong. The
dashboard's status (`GET /v1/status`, field `managed`) lists the sources a
running nandi uses.

Policy files named in managed settings should be absolute paths in a
directory users cannot write. The install scripts write the
[policy packs](../policy/packs.md) you choose there.

## Reporting to a central dashboard

Every machine can report its AI footprint (agents, MCP servers, hooks,
skills, and what bypasses nandi) to one central nandi, where the AI
footprint card shows the whole fleet. See [AI footprint](../guides/discovery.md).

On the central nandi, set a second token that can do nothing but report:

```yaml
admin:
  listen: 0.0.0.0:8788
  token: env:NANDI_ADMIN_TOKEN          # for people and the CLI
  report_token: env:NANDI_REPORT_TOKEN  # for the fleet: POST /v1/inventory only
```

In the managed settings for the fleet, point reports at it:

```yaml
report:
  url: https://nandi.corp.example
  token: <the report token>
```

The launch agent, scheduled task or systemd timer then runs
`nandi discover --report` at login and every 6 hours with no other
arguments. Managed settings are readable by every user on the machine,
which is why the fleet gets the report token and never the admin token.

## macOS with Jamf Pro

1. **Settings.** Computers > Configuration Profiles > New >
   Application & Custom Settings > Upload. Use the preference domain
   `io.github.dmdhrumilmistry.nandi` and upload
   `deploy/mdm/macos/io.github.dmdhrumilmistry.nandi.plist` after
   editing it. Its keys mirror `nandi.yaml`, and anything easier written as
   YAML can go under the `Config` key. Scope it to the computers.
   Other MDMs (Kandji, Mosyle, Intune for macOS) take
   `deploy/mdm/macos/nandi.mobileconfig`, which wraps the same settings.
2. **Install.** Add `deploy/mdm/macos/install-nandi.sh` as a script and run
   it from a policy. It takes three parameters:
   - Parameter 4 is the version, for example `v0.2.0`. It defaults to the
     latest release.
   - Parameter 5 is a comma-separated list of policy packs. It defaults to
     `coding-agent,payments`.
   - Set parameter 6 to `no-agents` to skip the launch agents.

   The script downloads the release for the Mac's architecture and checks
   its SHA-256. It installs `/usr/local/bin/nandi` and writes the packs to
   `/Library/Application Support/nandi/policies`. It also installs two
   launch agents, `nandi run` and `nandi discover --report`, and starts them
   for the user logged in now.
3. **Coverage.** Add `deploy/mdm/macos/jamf-extension-attribute.sh` as a
   script extension attribute. It reports, for example,
   `3 of 4 MCP servers via nandi; hooks 1 of 2`, and starts with `all:`
   when nothing bypasses nandi. A smart group on "does not start with
   all" finds the Macs to follow up.
4. **Coding agents.** Set parameter 7 to `agent-hooks` and the install
   script enforces nandi hooks for every agent that supports it, with
   `nandi hook-config all --managed --write`: Claude Code, Codex, Gemini
   CLI, Copilot CLI and Windsurf (see [Coding agents](../guides/coding-agents.md)).
   Alternatively push `deploy/mdm/claude-code-managed-settings.json` as
   Claude Code's managed settings file. On macOS that is
   `/Library/Application Support/ClaudeCode/managed-settings.json`; see
   Claude Code's [settings documentation](https://docs.claude.com/en/docs/claude-code/settings)
   for the path on each platform. The file installs the nandi hooks for
   every user, and users cannot remove them.

Each user's nandi keeps its data in `~/.config/nandi/nandi-data` and logs
to `~/Library/Logs/nandi.log`.

## Windows with Intune

1. **Settings.** Devices > Configuration > Import ADMX. Import
   `deploy/mdm/windows/nandi.admx` with `en-US/nandi.adml`, then create a
   profile from the imported template: nandi > Managed settings. Enter the
   YAML one line per row. It is stored in
   `HKLM\SOFTWARE\Policies\nandi\Config`. With Group Policy, copy the two
   files to the policy definitions store and use the same setting.
   Alternatively, have `Install-Nandi.ps1 -ManagedSettings managed.yaml`
   install a file as `C:\ProgramData\nandi\managed.yaml`.
2. **Install.** Package `Install-Nandi.ps1` as a Win32 app (wrap it with
   the Microsoft Win32 Content Prep Tool):
   - install command
     `powershell.exe -ExecutionPolicy Bypass -File Install-Nandi.ps1`
   - uninstall command
     `powershell.exe -ExecutionPolicy Bypass -File Uninstall-Nandi.ps1`
   - detection rule: the custom script `Detect-Nandi.ps1`

   The installer handles x64 and ARM64. It checks the download's SHA-256
   and installs to `C:\Program Files\nandi`, adding it to `PATH`. It makes
   `C:\ProgramData\nandi` writable by administrators only and writes the
   packs there. It also registers two tasks that run at every user's logon:
   `nandi` (`nandi run`) and `nandi discover` (also every 6 hours).
3. **Coding agents.** `Install-Nandi.ps1 -AgentHooks` enforces nandi hooks
   for every agent that supports it (`nandi hook-config all --managed --write`),
   or deploy the Claude Code managed settings file yourself. On Windows its command should name the config as
   `%LOCALAPPDATA%\nandi\nandi.yaml`.

Each user's nandi keeps its data in `%LOCALAPPDATA%\nandi\nandi-data`.

## Linux

Install the static binary to `/usr/local/bin/nandi` with your
configuration tool. Then lay down the files from `deploy/mdm/linux`:

```yaml
# Ansible
- name: nandi managed settings
  ansible.builtin.copy:
    src: deploy/mdm/linux/managed.yaml
    dest: /etc/nandi/managed.yaml
    owner: root
    mode: "0644"
- name: nandi policy packs
  ansible.builtin.shell: nandi policy pack {{ item }} > /etc/nandi/policies/{{ item }}.yaml
  loop: [coding-agent, payments]
- name: nandi user units
  ansible.builtin.copy:
    src: "deploy/mdm/linux/{{ item }}"
    dest: /etc/systemd/user/
    mode: "0644"
  loop: [nandi.service, nandi-discover.service, nandi-discover.timer]
- name: enable for every user
  ansible.builtin.command: systemctl --global enable nandi.service nandi-discover.timer
```

Put pieces that differ by team into `/etc/nandi/managed.d/` (for example
`20-payments-team.yaml`). Files there merge in name order after
`managed.yaml`. For servers rather than laptops, see
[Deployment](deployment.md).

## What managed settings cannot do

Managed settings control how nandi behaves. They cannot make an agent use
nandi. A user who points an agent straight at an API, or removes a wrapped
MCP server from a client config, bypasses it. Two things close that gap:
- the managed hooks of Claude Code, Codex, Copilot CLI and Windsurf, which
  users cannot remove
- the footprint reports, which show every server that bypasses nandi, per
  machine
