# Fleet deployment kits

Files for rolling nandi out to laptops and workstations with a device
management tool. The guide is [Fleets: Jamf, Intune and Linux](../../docs/operations/mdm.md).

| File | Use |
|---|---|
| `macos/io.github.dmdhrumilmistry.nandi.plist` | managed settings for Jamf Pro (Application & Custom Settings) |
| `macos/nandi.mobileconfig` | the same settings as a configuration profile for other MDMs |
| `macos/install-nandi.sh` | install script for a Jamf policy (binary, policy packs, launch agents) |
| `macos/io.github.dmdhrumilmistry.nandi.run.plist` | launch agent: `nandi run` for every user |
| `macos/io.github.dmdhrumilmistry.nandi.discover.plist` | launch agent: `nandi discover --report` at login and every 6 hours |
| `macos/jamf-extension-attribute.sh` | Jamf extension attribute reporting nandi coverage |
| `windows/nandi.admx`, `windows/en-US/nandi.adml` | administrative template for Intune and Group Policy |
| `windows/Install-Nandi.ps1` | installer for an Intune Win32 app (binary, policy packs, scheduled tasks) |
| `windows/Detect-Nandi.ps1`, `windows/Uninstall-Nandi.ps1` | Intune detection rule and uninstall command |
| `linux/managed.yaml` | example managed settings for `/etc/nandi/managed.yaml` |
| `linux/nandi.service`, `linux/nandi-discover.*` | systemd user units |
| `claude-code-managed-settings.json` | Claude Code managed settings that install the nandi hooks |

Replace `nandi.corp.example` and `REPLACE-WITH-THE-SERVER-REPORT-TOKEN` with
your central nandi's URL and its `admin.report_token`, and check settings
with `nandi managed --file FILE` before deploying them.
