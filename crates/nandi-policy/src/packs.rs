//! Policy packs bundled with the binary (`nandi policy packs`, the dashboard).
//!
//! Each pack is an ordinary rule file from `examples/packs`, ready to save
//! under `policies/` and list in `policy.rules`.

pub struct Pack {
    pub name: &'static str,
    pub yaml: &'static str,
}

impl Pack {
    /// The pack's one-line summary: the text after `# Pack:` on its first line.
    pub fn summary(&self) -> &'static str {
        self.yaml.lines().next().and_then(|l| l.strip_prefix("# Pack:")).map(str::trim).unwrap_or("")
    }
}

pub const PACKS: &[Pack] = &[
    Pack { name: "coding-agent", yaml: include_str!("../../../examples/packs/coding-agent.yaml") },
    Pack { name: "payments", yaml: include_str!("../../../examples/packs/payments.yaml") },
    Pack { name: "protect-production", yaml: include_str!("../../../examples/packs/protect-production.yaml") },
    Pack { name: "sensitive-saas", yaml: include_str!("../../../examples/packs/sensitive-saas.yaml") },
    Pack { name: "tainted-outbound", yaml: include_str!("../../../examples/packs/tainted-outbound.yaml") },
];

pub fn find(name: &str) -> Option<&'static Pack> {
    PACKS.iter().find(|p| p.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pack_has_a_summary_and_unique_name() {
        let mut names: Vec<&str> = PACKS.iter().map(|p| p.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), PACKS.len());
        for p in PACKS {
            assert!(!p.summary().is_empty(), "{} has no summary", p.name);
        }
        assert!(find("payments").is_some());
        assert!(find("nope").is_none());
    }

    #[test]
    fn every_pack_loads_with_the_example_rules() {
        // Packs are added next to the example rules, so ids must not clash.
        let examples = include_str!("../../../examples/policies/rules.yaml");
        let mut sources = vec![examples];
        sources.extend(PACKS.iter().map(|p| p.yaml));
        let set = crate::PolicySet::from_sources(Default::default(), None, None, &sources).unwrap();
        assert!(set.validate().is_empty(), "{:?}", set.validate());
    }
}
