//! Users of the admin API and dashboard: who they are, what their roles
//! allow, and their bearer tokens.
//!
//! Three kinds of principal reach the admin API:
//!
//! - the **admin token** (`admin.token`), a break-glass account with every
//!   permission, named `admin`;
//! - **users**, each with roles and their own token. Users come from
//!   `admin.users` in the configuration (read-only here) or are created
//!   from the dashboard and kept in the state store; only the SHA-256 of a
//!   token is stored, and a new token is shown once;
//! - **local** access over loopback when no admin token is configured (a
//!   single-user laptop), with every permission, as before users existed.
//!
//! The report token (`admin.report_token`) is a principal with the
//! `reporter` role only.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use nandi_core::StateStore;
use nandi_core::config::{AdminConfig, Role, resolve_secret};
use nandi_core::util::{new_id, now_ms, sha256_hex};

/// State store prefix of dashboard-created users.
const PREFIX: &str = "user/";
/// Name of the admin-token principal.
pub const BREAK_GLASS: &str = "admin";
/// Name of the loopback principal when no admin token is configured.
pub const LOCAL: &str = "local";

/// Something a principal may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read events, sessions, approvals, pins, servers, usage, the map,
    /// inventories, policies and the audit trail.
    Read,
    /// Approvals, the kill switch, pins, accepting server binaries,
    /// resetting behaviour models, revoking tokens.
    Operate,
    /// Propose policy changes.
    PolicyPropose,
    /// Approve, apply, reject and roll back policy changes; reload policy files.
    PolicyApprove,
    /// Create, change and delete users.
    ManageUsers,
    /// Submit coding-agent hook events.
    Hook,
    /// Report inventories.
    Report,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Operate => "operate",
            Permission::PolicyPropose => "policy_propose",
            Permission::PolicyApprove => "policy_approve",
            Permission::ManageUsers => "manage_users",
            Permission::Hook => "hook",
            Permission::Report => "report",
        }
    }

    pub const ALL: [Permission; 7] = [
        Permission::Read,
        Permission::Operate,
        Permission::PolicyPropose,
        Permission::PolicyApprove,
        Permission::ManageUsers,
        Permission::Hook,
        Permission::Report,
    ];
}

/// Permissions a role grants.
pub fn grants(role: Role) -> &'static [Permission] {
    use Permission::*;
    match role {
        Role::Viewer => &[Read],
        Role::Operator => &[Read, Operate],
        Role::PolicyEditor => &[Read, PolicyPropose],
        Role::PolicyApprover => &[Read, PolicyPropose, PolicyApprove],
        Role::Admin => &Permission::ALL,
        Role::Hook => &[Hook],
        Role::Reporter => &[Report],
    }
}

/// Where a principal comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// The admin token.
    AdminToken,
    /// Loopback without a configured admin token.
    Local,
    /// `admin.users` in the configuration.
    Config,
    /// Created from the dashboard or the API.
    Dashboard,
    /// The report token.
    ReportToken,
}

/// An authenticated caller of the admin API.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Principal {
    pub name: String,
    pub roles: Vec<Role>,
    pub origin: Origin,
}

impl Principal {
    pub fn admin() -> Self {
        Self { name: BREAK_GLASS.into(), roles: vec![Role::Admin], origin: Origin::AdminToken }
    }

    pub fn local() -> Self {
        Self { name: LOCAL.into(), roles: vec![Role::Admin], origin: Origin::Local }
    }

    pub fn reporter() -> Self {
        Self { name: "report-token".into(), roles: vec![Role::Reporter], origin: Origin::ReportToken }
    }

    pub fn can(&self, p: Permission) -> bool {
        self.roles.iter().any(|r| grants(*r).contains(&p))
    }

    pub fn permissions(&self) -> Vec<Permission> {
        Permission::ALL.into_iter().filter(|p| self.can(*p)).collect()
    }
}

/// A stored user. The token itself is never stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub roles: Vec<Role>,
    #[serde(skip_serializing)]
    pub token_sha256: String,
    pub origin: Origin,
    #[serde(default)]
    pub disabled: bool,
    pub created_ms: u64,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub updated_ms: u64,
}

/// The stored form, which keeps the token hash.
#[derive(Serialize, Deserialize)]
struct Stored {
    name: String,
    roles: Vec<Role>,
    token_sha256: String,
    #[serde(default)]
    disabled: bool,
    created_ms: u64,
    #[serde(default)]
    created_by: String,
    #[serde(default)]
    updated_ms: u64,
}

/// Why a user operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum UserError {
    Invalid(String),
    NotFound,
    Exists,
    ReadOnly,
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserError::Invalid(m) => f.write_str(m),
            UserError::NotFound => f.write_str("no such user"),
            UserError::Exists => f.write_str("a user with that name exists"),
            UserError::ReadOnly => f.write_str("this user is defined in the configuration and cannot be changed here"),
        }
    }
}

/// All users, with a token-hash index for authentication.
pub struct Users {
    store: Arc<dyn StateStore>,
    users: RwLock<BTreeMap<String, User>>,
}

/// Compare digests without an early exit.
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A fresh random token: `nandi_` and 48 hex characters.
fn new_token() -> String {
    let a = new_id().replace('-', "");
    let b = new_id().replace('-', "");
    format!("nandi_{}", &format!("{a}{b}")[..48])
}

fn valid_name(name: &str) -> Result<(), UserError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
    if !ok {
        return Err(UserError::Invalid("names are 1 to 64 letters, digits, '.', '_', '-' or '@'".into()));
    }
    if [BREAK_GLASS, LOCAL, "report-token"].contains(&name) {
        return Err(UserError::Invalid(format!("'{name}' is reserved")));
    }
    Ok(())
}

fn valid_roles(roles: &[Role]) -> Result<(), UserError> {
    if roles.is_empty() {
        return Err(UserError::Invalid("give at least one role".into()));
    }
    Ok(())
}

impl Users {
    pub fn new(cfg: &AdminConfig, store: Arc<dyn StateStore>) -> Self {
        let mut users = BTreeMap::new();
        for key in store.keys(PREFIX) {
            if let Some(bytes) = store.get(&key)
                && let Ok(s) = serde_json::from_slice::<Stored>(&bytes)
            {
                users.insert(
                    s.name.clone(),
                    User {
                        name: s.name,
                        roles: s.roles,
                        token_sha256: s.token_sha256,
                        origin: Origin::Dashboard,
                        disabled: s.disabled,
                        created_ms: s.created_ms,
                        created_by: s.created_by,
                        updated_ms: s.updated_ms,
                    },
                );
            }
        }
        // Configured users win over stored ones of the same name.
        for u in &cfg.users {
            match resolve_secret(&u.token) {
                Ok(t) if !t.is_empty() => {
                    users.insert(
                        u.name.clone(),
                        User {
                            name: u.name.clone(),
                            roles: u.roles.clone(),
                            token_sha256: sha256_hex(t.trim()),
                            origin: Origin::Config,
                            disabled: false,
                            created_ms: 0,
                            created_by: "configuration".into(),
                            updated_ms: 0,
                        },
                    );
                }
                _ => tracing::error!(user = %u.name, "admin.users: token cannot be resolved; user disabled"),
            }
        }
        Self { store, users: RwLock::new(users) }
    }

    fn save(&self, u: &User) {
        let s = Stored {
            name: u.name.clone(),
            roles: u.roles.clone(),
            token_sha256: u.token_sha256.clone(),
            disabled: u.disabled,
            created_ms: u.created_ms,
            created_by: u.created_by.clone(),
            updated_ms: u.updated_ms,
        };
        if let Ok(bytes) = serde_json::to_vec(&s) {
            self.store.put(&format!("{PREFIX}{}", u.name), &bytes);
        }
    }

    /// The enabled user whose token hashes to `token_sha256`.
    pub fn authenticate(&self, token_sha256: &str) -> Option<Principal> {
        let users = self.users.read();
        users.values().find(|u| !u.disabled && ct_eq(&u.token_sha256, token_sha256)).map(|u| Principal {
            name: u.name.clone(),
            roles: u.roles.clone(),
            origin: u.origin,
        })
    }

    pub fn list(&self) -> Vec<User> {
        self.users.read().values().cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.users.read().is_empty()
    }

    /// Create a user; returns the token, shown once.
    pub fn create(&self, name: &str, roles: Vec<Role>, by: &str) -> Result<(User, String), UserError> {
        valid_name(name)?;
        valid_roles(&roles)?;
        let mut users = self.users.write();
        if users.contains_key(name) {
            return Err(UserError::Exists);
        }
        let token = new_token();
        let now = now_ms();
        let u = User {
            name: name.into(),
            roles,
            token_sha256: sha256_hex(&token),
            origin: Origin::Dashboard,
            disabled: false,
            created_ms: now,
            created_by: by.into(),
            updated_ms: now,
        };
        self.save(&u);
        users.insert(name.into(), u.clone());
        Ok((u, token))
    }

    fn update_with(&self, name: &str, f: impl FnOnce(&mut User)) -> Result<User, UserError> {
        let mut users = self.users.write();
        let u = users.get_mut(name).ok_or(UserError::NotFound)?;
        if u.origin == Origin::Config {
            return Err(UserError::ReadOnly);
        }
        f(u);
        u.updated_ms = now_ms();
        let u = u.clone();
        self.save(&u);
        Ok(u)
    }

    /// Change roles and/or disable or enable a user.
    pub fn update(&self, name: &str, roles: Option<Vec<Role>>, disabled: Option<bool>) -> Result<User, UserError> {
        if let Some(r) = &roles {
            valid_roles(r)?;
        }
        self.update_with(name, |u| {
            if let Some(r) = roles {
                u.roles = r;
            }
            if let Some(d) = disabled {
                u.disabled = d;
            }
        })
    }

    /// Replace a user's token; returns the new one, shown once.
    pub fn rotate(&self, name: &str) -> Result<String, UserError> {
        let token = new_token();
        let hash = sha256_hex(&token);
        self.update_with(name, |u| u.token_sha256 = hash)?;
        Ok(token)
    }

    pub fn delete(&self, name: &str) -> Result<(), UserError> {
        let mut users = self.users.write();
        match users.get(name) {
            None => return Err(UserError::NotFound),
            Some(u) if u.origin == Origin::Config => return Err(UserError::ReadOnly),
            Some(_) => {}
        }
        users.remove(name);
        self.store.delete(&format!("{PREFIX}{name}"));
        Ok(())
    }

    /// Enabled users with a role that grants `p`.
    pub fn count_with(&self, p: Permission) -> usize {
        self.users.read().values().filter(|u| !u.disabled && u.roles.iter().any(|r| grants(*r).contains(&p))).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::MemoryStore;
    use nandi_core::config::UserConfig;

    fn users(cfg: &AdminConfig) -> (Users, Arc<dyn StateStore>) {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStore::new());
        (Users::new(cfg, store.clone()), store)
    }

    #[test]
    fn roles_grant_permissions() {
        let p = |roles: &[Role]| Principal { name: "x".into(), roles: roles.to_vec(), origin: Origin::Dashboard };
        assert!(p(&[Role::Viewer]).can(Permission::Read) && !p(&[Role::Viewer]).can(Permission::Operate));
        assert!(p(&[Role::Operator]).can(Permission::Operate));
        assert!(!p(&[Role::PolicyEditor]).can(Permission::PolicyApprove));
        assert!(p(&[Role::PolicyApprover]).can(Permission::PolicyPropose));
        assert_eq!(p(&[Role::Admin]).permissions().len(), Permission::ALL.len());
        assert_eq!(p(&[Role::Hook]).permissions(), [Permission::Hook]);
        assert!(!p(&[Role::Reporter]).can(Permission::Read));
        assert!(p(&[Role::Viewer, Role::Operator]).can(Permission::Operate));
    }

    #[test]
    fn lifecycle_tokens_are_hashed_and_shown_once() {
        let (u, store) = users(&AdminConfig::default());
        let (user, token) = u.create("asha", vec![Role::Operator], "admin").unwrap();
        assert!(token.starts_with("nandi_") && token.len() == 54);
        assert_eq!(u.authenticate(&sha256_hex(&token)).unwrap().name, "asha");
        assert!(u.authenticate(&sha256_hex("nope")).is_none());
        // The token is not in the API form, and only its hash is stored.
        assert!(serde_json::to_string(&user).unwrap().find("token").is_none());
        let raw = String::from_utf8(store.get("user/asha").unwrap()).unwrap();
        assert!(!raw.contains(&token) && raw.contains(&sha256_hex(&token)));
        assert_eq!(u.create("asha", vec![Role::Viewer], "admin").unwrap_err(), UserError::Exists);
        assert!(matches!(u.create("admin", vec![Role::Viewer], "x"), Err(UserError::Invalid(_))));
        assert!(matches!(u.create("bad name", vec![Role::Viewer], "x"), Err(UserError::Invalid(_))));
        assert!(matches!(u.create("ok", vec![], "x"), Err(UserError::Invalid(_))));

        // Disable, rotate, change roles, and survive a restart.
        u.update("asha", None, Some(true)).unwrap();
        assert!(u.authenticate(&sha256_hex(&token)).is_none());
        u.update("asha", Some(vec![Role::Viewer]), Some(false)).unwrap();
        let fresh = u.rotate("asha").unwrap();
        assert!(u.authenticate(&sha256_hex(&token)).is_none());
        let again = Users::new(&AdminConfig::default(), store.clone());
        let p = again.authenticate(&sha256_hex(&fresh)).unwrap();
        assert_eq!(p.roles, [Role::Viewer]);
        again.delete("asha").unwrap();
        assert!(again.authenticate(&sha256_hex(&fresh)).is_none());
        assert!(store.get("user/asha").is_none());
        assert_eq!(again.delete("asha").unwrap_err(), UserError::NotFound);
    }

    #[test]
    fn configured_users_are_read_only() {
        let cfg = AdminConfig {
            users: vec![UserConfig { name: "ci".into(), roles: vec![Role::Viewer], token: "ci-token".into() }],
            ..AdminConfig::default()
        };
        let (u, _) = users(&cfg);
        assert_eq!(u.authenticate(&sha256_hex("ci-token")).unwrap().origin, Origin::Config);
        assert_eq!(u.update("ci", None, Some(true)).unwrap_err(), UserError::ReadOnly);
        assert_eq!(u.rotate("ci").unwrap_err(), UserError::ReadOnly);
        assert_eq!(u.delete("ci").unwrap_err(), UserError::ReadOnly);
        assert_eq!(u.count_with(Permission::Read), 1);
    }
}
