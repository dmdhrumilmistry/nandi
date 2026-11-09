//! `nandi init`: write a starter configuration and policies.
//!
//! The files are the ones in the repository's `examples/` directory, so the
//! documentation and the generated config never drift apart.

use std::path::Path;

use anyhow::{Context, bail};

/// `(relative path, contents)` of every generated file.
pub const FILES: &[(&str, &str)] = &[
    ("nandi.yaml", include_str!("../../../examples/nandi.yaml")),
    ("policies/rules.yaml", include_str!("../../../examples/policies/rules.yaml")),
    ("policies/policy.cedar", include_str!("../../../examples/policies/policy.cedar")),
];

pub fn run(dir: &Path, force: bool) -> anyhow::Result<()> {
    if !force {
        let existing: Vec<String> =
            FILES.iter().map(|(p, _)| dir.join(p)).filter(|p| p.exists()).map(|p| p.display().to_string()).collect();
        if !existing.is_empty() {
            bail!("refusing to overwrite {} (use --force)", existing.join(", "));
        }
    }
    for (rel, text) in FILES {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
    }
    let cfg = dir.join("nandi.yaml");
    println!("\nnext steps:");
    println!("  nandi policy validate -c {}", cfg.display());
    println!("  nandi run -c {}", cfg.display());
    println!("  open http://127.0.0.1:8788/ for the dashboard");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::Config;
    use nandi_policy::PolicySet;

    #[test]
    fn generated_files_load_and_validate() {
        let dir = tempfile::tempdir().unwrap();
        run(dir.path(), false).unwrap();
        assert!(run(dir.path(), false).is_err());
        run(dir.path(), true).unwrap();
        let cfg = Config::load(&dir.path().join("nandi.yaml")).unwrap();
        let policy = PolicySet::load(&cfg.policy, dir.path()).unwrap();
        assert!(policy.validate().is_empty(), "{:?}", policy.validate());
    }
}
