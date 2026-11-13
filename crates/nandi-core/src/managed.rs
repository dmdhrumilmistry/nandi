//! Managed settings pushed by an MDM or configuration management tool.
//!
//! Managed settings are merged over the user's `nandi.yaml` wherever a
//! configuration is loaded, so an administrator can require settings (mode,
//! policies, approved servers, the admin token) that a user cannot change.
//! They are read from system locations only:
//!
//! | Platform | Source | Pushed by |
//! |---|---|---|
//! | all but Windows | `/etc/nandi/managed.yaml`, then `/etc/nandi/managed.d/*.yaml` in name order | Ansible, Puppet, Chef, Salt |
//! | macOS | `/Library/Application Support/nandi/managed.yaml` | Jamf, Kandji, Mosyle scripts |
//! | macOS | `/Library/Managed Preferences/io.github.dmdhrumilmistry.nandi.plist` | a configuration profile (Jamf, Kandji, Mosyle, Intune) |
//! | Windows | `%ProgramData%\nandi\managed.yaml` | Intune or GPO file deployment |
//! | Windows | `HKLM\SOFTWARE\Policies\nandi`, value `Config` (YAML text) | Intune (ADMX) or Group Policy |
//!
//! Later sources win. Maps merge key by key; lists and scalars replace. A
//! configuration profile or the registry can also give the whole document
//! as YAML text under `Config` (the plist key `Config` on macOS), merged
//! before the profile's other keys.
//!
//! There is deliberately no flag or environment variable to skip managed
//! settings. A managed file that users other than the owner can write is
//! ignored with a warning, since anyone could otherwise change it.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::{Error, Result};

/// Preference domain of the macOS configuration profile.
pub const MACOS_DOMAIN: &str = "io.github.dmdhrumilmistry.nandi";
/// Registry key of the Windows policy, under `HKEY_LOCAL_MACHINE`.
pub const WINDOWS_POLICY_KEY: &str = r"SOFTWARE\Policies\nandi";

/// Managed settings found on this machine.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Managed {
    /// The merged settings, a YAML/JSON mapping.
    pub value: Map<String, Value>,
    /// Where they came from, in merge order.
    pub sources: Vec<String>,
    /// Sources that were skipped, and why.
    pub warnings: Vec<String>,
}

impl Managed {
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// The merged settings as YAML.
    pub fn to_yaml(&self) -> String {
        serde_saphyr::to_string(&Value::Object(self.value.clone())).unwrap_or_default()
    }

    /// Merge one document from `source` over what was loaded so far.
    fn add(&mut self, source: String, doc: Value) -> Result<()> {
        match doc {
            Value::Object(map) => {
                merge(&mut self.value, map);
                self.sources.push(source);
                Ok(())
            }
            Value::Null => Ok(()),
            _ => Err(Error::Config(format!("managed settings in {source} must be a mapping"))),
        }
    }

    /// Parse YAML text from `source` and merge it.
    fn add_yaml(&mut self, source: String, text: &str) -> Result<()> {
        // Notepad and Windows PowerShell 5.1 write a byte order mark.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        if text.trim().is_empty() {
            return Ok(());
        }
        let doc: Value =
            serde_saphyr::from_str(text).map_err(|e| Error::Config(format!("managed settings in {source}: {e}")))?;
        self.add(source, doc)
    }

    /// Read a managed YAML file, if it exists and only its owner can write it.
    fn add_file(&mut self, path: &Path) -> Result<()> {
        let Ok(meta) = std::fs::metadata(path) else { return Ok(()) };
        if !meta.is_file() {
            return Ok(());
        }
        if let Some(why) = writable_by_others(&meta) {
            self.warnings.push(format!("ignoring {}: {why}", path.display()));
            return Ok(());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading managed settings {}: {e}", path.display())))?;
        self.add_yaml(path.display().to_string(), &text)
    }

    /// Read `dir/*.yaml` (and `*.yml`) in name order.
    fn add_dir(&mut self, dir: &Path) -> Result<()> {
        let Ok(entries) = std::fs::read_dir(dir) else { return Ok(()) };
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
            .collect();
        files.sort();
        for f in files {
            self.add_file(&f)?;
        }
        Ok(())
    }
}

/// Deep merge: maps merge key by key, anything else replaces.
pub fn merge(base: &mut Map<String, Value>, over: Map<String, Value>) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(Value::Object(b)), Value::Object(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

#[cfg(unix)]
fn writable_by_others(meta: &std::fs::Metadata) -> Option<&'static str> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode();
    if mode & 0o002 != 0 {
        Some("it is writable by every user")
    } else if mode & 0o020 != 0 {
        Some("it is writable by its group")
    } else {
        None
    }
}

#[cfg(not(unix))]
fn writable_by_others(_meta: &std::fs::Metadata) -> Option<&'static str> {
    // %ProgramData% is admin-writable only by default; the ACL is the
    // deployment's responsibility.
    None
}

/// Load the managed settings of this machine. Missing sources are skipped;
/// a source that exists but cannot be parsed is an error, so a broken
/// deployment is noticed instead of silently ignored.
pub fn load() -> Result<Managed> {
    let mut m = Managed::default();
    #[cfg(not(windows))]
    {
        m.add_file(Path::new("/etc/nandi/managed.yaml"))?;
        m.add_dir(Path::new("/etc/nandi/managed.d"))?;
    }
    #[cfg(target_os = "macos")]
    {
        m.add_file(Path::new("/Library/Application Support/nandi/managed.yaml"))?;
        macos::add_profile(&mut m, Path::new(&format!("/Library/Managed Preferences/{MACOS_DOMAIN}.plist")))?;
    }
    #[cfg(windows)]
    {
        let data =
            std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        m.add_file(&data.join("nandi").join("managed.yaml"))?;
        windows::add_policy(&mut m)?;
    }
    Ok(m)
}

/// Load managed settings from explicit YAML files, in order (tests and
/// `nandi managed --file`).
pub fn load_files(paths: &[&Path]) -> Result<Managed> {
    let mut m = Managed::default();
    for p in paths {
        if p.is_dir() {
            m.add_dir(p)?;
        } else {
            m.add_file(p)?;
        }
    }
    Ok(m)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    /// Convert a property list value to JSON. Dates and data become strings.
    fn to_json(v: plist::Value) -> Value {
        match v {
            plist::Value::Dictionary(d) => Value::Object(d.into_iter().map(|(k, v)| (k, to_json(v))).collect()),
            plist::Value::Array(a) => Value::Array(a.into_iter().map(to_json).collect()),
            plist::Value::Boolean(b) => Value::Bool(b),
            plist::Value::Integer(i) => {
                i.as_signed().map(Value::from).or_else(|| i.as_unsigned().map(Value::from)).unwrap_or(Value::Null)
            }
            plist::Value::Real(f) => serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null),
            plist::Value::String(s) => Value::String(s),
            plist::Value::Date(d) => Value::String(d.to_xml_format()),
            plist::Value::Data(d) => Value::String(hex::encode(d)),
            plist::Value::Uid(u) => Value::from(u.get()),
            _ => Value::Null,
        }
    }

    /// Managed preferences written by a configuration profile.
    pub fn add_profile(m: &mut Managed, path: &Path) -> Result<()> {
        if !path.is_file() {
            return Ok(());
        }
        let source = format!("configuration profile ({})", path.display());
        let v = plist::Value::from_file(path).map_err(|e| Error::Config(format!("reading {source}: {e}")))?;
        let Value::Object(mut map) = to_json(v) else {
            return Err(Error::Config(format!("{source} is not a dictionary")));
        };
        // macOS adds bookkeeping keys to managed preferences.
        map.retain(|k, _| !k.starts_with("Payload") && k != "PolicyLastUpdated");
        if let Some(Value::String(yaml)) = map.remove("Config") {
            m.add_yaml(format!("{source}, key Config"), &yaml)?;
        }
        if !map.is_empty() {
            m.add(source, Value::Object(map))?;
        }
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

    /// `HKLM\SOFTWARE\Policies\nandi`: `Config` holds YAML text (REG_SZ,
    /// REG_EXPAND_SZ or REG_MULTI_SZ, one line per string).
    pub fn add_policy(m: &mut Managed) -> Result<()> {
        let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(WINDOWS_POLICY_KEY, KEY_READ) else {
            return Ok(());
        };
        let source = format!(r"registry policy (HKLM\{WINDOWS_POLICY_KEY}\Config)");
        let text = match key.get_value::<String, _>("Config") {
            Ok(s) => s,
            Err(_) => match key.get_value::<Vec<String>, _>("Config") {
                Ok(lines) => lines.join("\n"),
                Err(_) => return Ok(()),
            },
        };
        m.add_yaml(source, &text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn merge_is_deep_for_maps_only() {
        let mut base =
            obj(json!({ "mode": "monitor", "admin": { "listen": "a", "ui": true }, "policy": { "rules": ["x"] } }));
        merge(
            &mut base,
            obj(json!({ "mode": "enforce", "admin": { "ui": false }, "policy": { "rules": ["y", "z"] } })),
        );
        assert_eq!(
            Value::Object(base),
            json!({ "mode": "enforce", "admin": { "listen": "a", "ui": false }, "policy": { "rules": ["y", "z"] } })
        );
    }

    #[test]
    fn files_merge_in_order_and_bad_files_are_errors() {
        let dir = std::env::temp_dir().join(format!("nandi-managed-{}", crate::util::new_id()));
        std::fs::create_dir_all(dir.join("d")).unwrap();
        let first = dir.join("managed.yaml");
        std::fs::write(&first, "mode: enforce\nservers: { on_unknown: deny }\n").unwrap();
        std::fs::write(dir.join("d/20-b.yaml"), "servers: { on_unpinned: ask }\n").unwrap();
        std::fs::write(dir.join("d/10-a.yml"), "servers: { on_unknown: alert }\n").unwrap();
        std::fs::write(dir.join("d/notes.txt"), "not yaml").unwrap();
        let m = load_files(&[&first, &dir.join("d"), &dir.join("missing.yaml")]).unwrap();
        assert_eq!(m.sources.len(), 3);
        assert!(m.sources[1].ends_with("10-a.yml"));
        assert_eq!(
            Value::Object(m.value.clone()),
            json!({ "mode": "enforce", "servers": { "on_unknown": "alert", "on_unpinned": "ask" } })
        );
        assert!(m.to_yaml().contains("on_unpinned: ask"));

        std::fs::write(&first, "\u{feff}mode: monitor\n").unwrap();
        assert_eq!(load_files(&[&first]).unwrap().value["mode"], "monitor", "a byte order mark is skipped");
        std::fs::write(&first, "- a list\n").unwrap();
        assert!(load_files(&[&first]).is_err());
        std::fs::write(&first, "mode: [unclosed\n").unwrap();
        assert!(load_files(&[&first]).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn files_others_can_write_are_ignored() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nandi-managed-{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("managed.yaml");
        std::fs::write(&f, "mode: monitor\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        let m = load_files(&[&f]).unwrap();
        assert!(m.is_empty() && m.warnings.len() == 1, "{m:?}");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!load_files(&[&f]).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
