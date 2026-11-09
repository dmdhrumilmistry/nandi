//! Argument predicates shared by YAML rules, sequences and plan steps.
//!
//! A matcher is written as a map of dotted argument paths to value matchers:
//!
//! ```yaml
//! args:
//!   table: { in: [users, payments] }
//!   "options.force": true
//!   path: { regex: "^/etc/" }
//! ```
//!
//! A value matcher is either a bare value (equality; a bare string containing
//! `*` or `?` is a glob, a bare array is `in`) or a map of operators that must
//! all hold. Regexes are compiled once at load time.

use std::borrow::Cow;

use regex::{Regex, RegexBuilder};
use serde_json::{Map, Number, Value};

use nandi_core::util::glob_match;

/// Upper bound for one compiled regex (program and lazy DFA), in bytes.
const REGEX_SIZE_LIMIT: usize = 256 * 1024;
/// Maximum nesting of `any` / `all` matchers.
const MAX_MATCHER_DEPTH: usize = 8;

/// One comparison operator.
#[derive(Debug, Clone)]
enum Op {
    Eq(Value),
    Ne(Value),
    In(Vec<Value>),
    NotIn(Vec<Value>),
    Glob(String),
    Regex(Regex),
    Prefix(String),
    NotPrefix(String),
    Suffix(String),
    Contains(Value),
    NotContains(Value),
    Lt(f64),
    Lte(f64),
    Gt(f64),
    Gte(f64),
    MaxLen(usize),
    Exists(bool),
    Any(Box<ValueMatcher>),
    All(Box<ValueMatcher>),
}

/// Conjunction of operators applied to a single (possibly missing) value.
#[derive(Debug, Clone, Default)]
pub struct ValueMatcher {
    ops: Vec<Op>,
}

impl ValueMatcher {
    /// Parse a value matcher from its YAML / JSON form.
    pub fn parse(spec: &Value) -> Result<Self, String> {
        Self::parse_depth(spec, 0)
    }

    fn parse_depth(spec: &Value, depth: usize) -> Result<Self, String> {
        if depth > MAX_MATCHER_DEPTH {
            return Err(format!("matcher nesting deeper than {MAX_MATCHER_DEPTH}"));
        }
        let ops = match spec {
            Value::Object(map) => {
                if map.is_empty() {
                    return Err("empty matcher map (use `eq: {}` to compare with an empty object)".into());
                }
                let mut ops = Vec::with_capacity(map.len());
                for (key, operand) in map {
                    ops.push(parse_op(key, operand, depth)?);
                }
                ops
            }
            Value::String(s) if s.contains(['*', '?']) => vec![Op::Glob(s.clone())],
            Value::Array(items) => vec![Op::In(items.clone())],
            other => vec![Op::Eq(other.clone())],
        };
        Ok(Self { ops })
    }

    /// Whether `value` (`None` when the path is missing or null) satisfies
    /// every operator.
    pub fn matches(&self, value: Option<&Value>) -> bool {
        self.ops.iter().all(|op| op_matches(op, value))
    }

    /// Number of compiled regexes, for load-time budgeting.
    fn regex_count(&self) -> usize {
        self.ops
            .iter()
            .map(|op| match op {
                Op::Regex(_) => 1,
                Op::Any(m) | Op::All(m) => m.regex_count(),
                _ => 0,
            })
            .sum()
    }
}

fn parse_op(key: &str, operand: &Value, depth: usize) -> Result<Op, String> {
    let string = |what: &str| -> Result<String, String> {
        operand.as_str().map(str::to_owned).ok_or_else(|| format!("`{what}` expects a string"))
    };
    let number =
        |what: &str| -> Result<f64, String> { as_number(operand).ok_or_else(|| format!("`{what}` expects a number")) };
    let list = |what: &str| -> Result<Vec<Value>, String> {
        match operand {
            Value::Array(items) => Ok(items.clone()),
            _ => Err(format!("`{what}` expects a list")),
        }
    };
    Ok(match key {
        "eq" => Op::Eq(operand.clone()),
        "ne" => Op::Ne(operand.clone()),
        "in" => Op::In(list("in")?),
        "not_in" => Op::NotIn(list("not_in")?),
        "glob" => Op::Glob(string("glob")?),
        "regex" => {
            let pattern = string("regex")?;
            let re = RegexBuilder::new(&pattern)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|e| format!("invalid regex {pattern:?}: {e}"))?;
            Op::Regex(re)
        }
        "prefix" => Op::Prefix(string("prefix")?),
        "not_prefix" => Op::NotPrefix(string("not_prefix")?),
        "suffix" => Op::Suffix(string("suffix")?),
        "contains" => Op::Contains(operand.clone()),
        "not_contains" => Op::NotContains(operand.clone()),
        "lt" => Op::Lt(number("lt")?),
        "lte" => Op::Lte(number("lte")?),
        "gt" => Op::Gt(number("gt")?),
        "gte" => Op::Gte(number("gte")?),
        "max_len" => Op::MaxLen(operand.as_u64().ok_or("`max_len` expects a non-negative integer")? as usize),
        "exists" => Op::Exists(operand.as_bool().ok_or("`exists` expects true or false")?),
        "any" => Op::Any(Box::new(ValueMatcher::parse_depth(operand, depth + 1)?)),
        "all" => Op::All(Box::new(ValueMatcher::parse_depth(operand, depth + 1)?)),
        other => return Err(format!("unknown matcher operator `{other}`")),
    })
}

fn op_matches(op: &Op, value: Option<&Value>) -> bool {
    let Some(v) = value else {
        return matches!(op, Op::Exists(false) | Op::Ne(_) | Op::NotIn(_) | Op::NotPrefix(_) | Op::NotContains(_));
    };
    match op {
        Op::Eq(x) => json_eq(v, x),
        Op::Ne(x) => !json_eq(v, x),
        Op::In(xs) => xs.iter().any(|x| json_eq(v, x)),
        Op::NotIn(xs) => !xs.iter().any(|x| json_eq(v, x)),
        Op::Glob(p) => as_text(v).is_some_and(|t| glob_match(p, &t)),
        Op::Regex(re) => as_text(v).is_some_and(|t| re.is_match(&t)),
        Op::Prefix(p) => as_text(v).is_some_and(|t| t.starts_with(p.as_str())),
        Op::NotPrefix(p) => !as_text(v).is_some_and(|t| t.starts_with(p.as_str())),
        Op::Suffix(p) => as_text(v).is_some_and(|t| t.ends_with(p.as_str())),
        Op::Contains(x) => contains(v, x),
        Op::NotContains(x) => !contains(v, x),
        Op::Lt(n) => as_number(v).is_some_and(|x| x < *n),
        Op::Lte(n) => as_number(v).is_some_and(|x| x <= *n),
        Op::Gt(n) => as_number(v).is_some_and(|x| x > *n),
        Op::Gte(n) => as_number(v).is_some_and(|x| x >= *n),
        Op::MaxLen(n) => match v {
            Value::String(s) => s.chars().count() <= *n,
            Value::Array(a) => a.len() <= *n,
            Value::Object(m) => m.len() <= *n,
            _ => as_text(v).is_some_and(|t| t.chars().count() <= *n),
        },
        Op::Exists(want) => *want,
        Op::Any(m) => match v {
            Value::Array(items) => items.iter().any(|i| m.matches(present(i))),
            other => m.matches(Some(other)),
        },
        Op::All(m) => match v {
            Value::Array(items) => items.iter().all(|i| m.matches(present(i))),
            other => m.matches(Some(other)),
        },
    }
}

/// `null` is treated the same as a missing value.
fn present(v: &Value) -> Option<&Value> {
    if v.is_null() { None } else { Some(v) }
}

/// Substring for strings, element equality for arrays, key presence for
/// objects.
fn contains(v: &Value, x: &Value) -> bool {
    match v {
        Value::Array(items) => items.iter().any(|i| json_eq(i, x)),
        Value::Object(map) => x.as_str().is_some_and(|k| map.contains_key(k)),
        _ => match (as_text(v), as_text(x)) {
            (Some(hay), Some(needle)) => hay.contains(needle.as_ref()),
            _ => false,
        },
    }
}

/// Scalar as text: strings borrowed, numbers and booleans formatted.
pub(crate) fn as_text(v: &Value) -> Option<Cow<'_, str>> {
    match v {
        Value::String(s) => Some(Cow::Borrowed(s)),
        Value::Number(n) => Some(Cow::Owned(n.to_string())),
        Value::Bool(b) => Some(Cow::Borrowed(if *b { "true" } else { "false" })),
        _ => None,
    }
}

/// Numbers, or strings that parse as a finite number.
fn as_number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok().filter(|f| f.is_finite()),
        _ => None,
    }
}

fn num_eq(a: &Number, b: &Number) -> bool {
    if let (Some(x), Some(y)) = (a.as_i64(), b.as_i64()) {
        return x == y;
    }
    if let (Some(x), Some(y)) = (a.as_u64(), b.as_u64()) {
        return x == y;
    }
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// Structural equality where numbers compare numerically and a number equals
/// a string that parses to the same number.
pub(crate) fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => num_eq(x, y),
        (Value::Number(_), Value::String(_)) | (Value::String(_), Value::Number(_)) => {
            matches!((as_number(a), as_number(b)), (Some(x), Some(y)) if x == y)
        }
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_eq(p, q)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, p)| y.get(k).is_some_and(|q| json_eq(p, q)))
        }
        _ => a == b,
    }
}

/// A pre-split dotted argument path such as `options.force` or `items.0.id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgPath {
    raw: String,
    segments: Vec<String>,
}

impl ArgPath {
    /// Split a dotted path. Empty segments are rejected.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.is_empty() || raw.split('.').any(str::is_empty) {
            return Err(format!("invalid argument path {raw:?}"));
        }
        Ok(Self { raw: raw.to_owned(), segments: raw.split('.').map(str::to_owned).collect() })
    }

    /// The path as written.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Resolve the path in `root`. A top-level key that literally contains
    /// dots wins over the split interpretation. Numeric segments index
    /// arrays. `null` resolves to `None`.
    pub fn lookup<'v>(&self, root: &'v Value) -> Option<&'v Value> {
        if self.segments.len() > 1
            && let Some(v) = root.as_object().and_then(|m| m.get(&self.raw))
        {
            return present(v);
        }
        let mut cur = root;
        for seg in &self.segments {
            cur = match cur {
                Value::Object(map) => map.get(seg)?,
                Value::Array(items) => items.get(seg.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        present(cur)
    }
}

/// A set of `path -> matcher` constraints that must all hold.
#[derive(Debug, Clone, Default)]
pub struct ArgsMatcher {
    fields: Vec<(ArgPath, ValueMatcher)>,
}

impl ArgsMatcher {
    /// Parse from a map of dotted paths to value matchers. `null` means no
    /// constraints.
    pub fn parse(spec: &Value) -> Result<Self, String> {
        match spec {
            Value::Null => Ok(Self::default()),
            Value::Object(map) => Self::from_map(map),
            _ => Err("`args` must be a map of argument paths to matchers".into()),
        }
    }

    fn from_map(map: &Map<String, Value>) -> Result<Self, String> {
        let mut fields = Vec::with_capacity(map.len());
        for (path, spec) in map {
            let m = ValueMatcher::parse(spec).map_err(|e| format!("args.{path}: {e}"))?;
            fields.push((ArgPath::parse(path)?, m));
        }
        Ok(Self { fields })
    }

    /// True when there are no constraints.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Whether `args` satisfies every constraint.
    pub fn matches(&self, args: &Value) -> bool {
        self.fields.iter().all(|(path, m)| m.matches(path.lookup(args)))
    }

    /// Number of compiled regexes.
    pub fn regex_count(&self) -> usize {
        self.fields.iter().map(|(_, m)| m.regex_count()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vm(spec: Value) -> ValueMatcher {
        ValueMatcher::parse(&spec).unwrap()
    }

    fn check(spec: Value, value: Value) -> bool {
        vm(spec).matches(present(&value))
    }

    #[test]
    fn bare_values() {
        assert!(check(json!("users"), json!("users")));
        assert!(!check(json!("users"), json!("Users")));
        assert!(check(json!("user*"), json!("USERS")));
        assert!(check(json!(true), json!(true)));
        assert!(!check(json!(true), json!("yes")));
        assert!(check(json!(5), json!(5.0)));
        assert!(check(json!(5), json!("5")));
        assert!(check(json!(["a", "b"]), json!("b")));
        assert!(!check(json!(["a", "b"]), json!("c")));
    }

    #[test]
    fn equality_operators() {
        assert!(check(json!({"eq": {"a": [1, 2]}}), json!({"a": [1.0, 2]})));
        assert!(check(json!({"ne": "x"}), json!("y")));
        assert!(!check(json!({"ne": "x"}), json!("x")));
        assert!(check(json!({"in": [1, 2, 3]}), json!(2)));
        assert!(check(json!({"not_in": ["prod"]}), json!("dev")));
        assert!(!check(json!({"not_in": ["prod"]}), json!("prod")));
        assert!(check(json!({"eq": 18446744073709551615u64}), json!(18446744073709551615u64)));
        assert!(!check(json!({"eq": 9007199254740993i64}), json!(9007199254740992i64)));
    }

    #[test]
    fn string_operators() {
        assert!(check(json!({"glob": "*.env"}), json!("prod.ENV")));
        assert!(check(json!({"regex": "^/etc/"}), json!("/etc/passwd")));
        assert!(!check(json!({"regex": "^/etc/"}), json!("/home/etc/")));
        assert!(check(json!({"regex": "^4\\d+$"}), json!(42)));
        assert!(check(json!({"prefix": "/tmp/"}), json!("/tmp/x")));
        assert!(check(json!({"not_prefix": "/tmp/"}), json!("/etc/x")));
        assert!(!check(json!({"not_prefix": "/tmp/"}), json!("/tmp/x")));
        assert!(check(json!({"suffix": ".pem"}), json!("key.pem")));
        assert!(check(json!({"contains": "DROP"}), json!("x; DROP TABLE")));
        assert!(check(json!({"not_contains": "DROP"}), json!("select 1")));
        assert!(check(json!({"contains": "admin"}), json!(["user", "admin"])));
        assert!(check(json!({"contains": "force"}), json!({"force": false})));
        assert!(check(json!({"max_len": 3}), json!("abc")));
        assert!(!check(json!({"max_len": 3}), json!("abcd")));
        assert!(check(json!({"max_len": 2}), json!([1, 2])));
        assert!(!check(json!({"max_len": 1}), json!([1, 2])));
    }

    #[test]
    fn numeric_operators() {
        assert!(check(json!({"lt": 100}), json!(99.5)));
        assert!(!check(json!({"lt": 100}), json!(100)));
        assert!(check(json!({"lte": 100}), json!(100)));
        assert!(check(json!({"gt": 10, "lte": 20}), json!("15")));
        assert!(!check(json!({"gt": 10, "lte": 20}), json!(25)));
        assert!(check(json!({"gte": 0}), json!(0)));
        assert!(!check(json!({"gte": 0}), json!("abc")));
        assert!(!check(json!({"gte": 0}), json!("NaN")));
    }

    #[test]
    fn missing_values() {
        let m = |spec| vm(spec).matches(None);
        assert!(m(json!({"exists": false})));
        assert!(!m(json!({"exists": true})));
        assert!(m(json!({"ne": "x"})));
        assert!(m(json!({"not_in": ["x"]})));
        assert!(m(json!({"not_prefix": "x"})));
        assert!(m(json!({"not_contains": "x"})));
        assert!(!m(json!("x")));
        assert!(!m(json!({"lt": 5})));
        assert!(!m(json!({"any": "x"})));
        assert!(check(json!({"exists": true}), json!(0)));
    }

    #[test]
    fn any_and_all() {
        let urls = json!(["https://ok.example", "http://evil.test/x"]);
        assert!(check(json!({"any": {"prefix": "http://"}}), urls.clone()));
        assert!(!check(json!({"all": {"prefix": "https://"}}), urls));
        assert!(check(json!({"all": {"prefix": "https://"}}), json!([])));
        assert!(check(json!({"any": {"gt": 5}}), json!(7)));
        let nested = json!([{"to": "a@corp.com"}, {"to": "b@evil.com"}]);
        assert!(!check(json!({"any": {"glob": "*"}}), nested.clone()), "glob only applies to scalars");
        assert!(check(json!({"any": {"eq": {"to": "b@evil.com"}}}), nested));
    }

    #[test]
    fn parse_errors() {
        assert!(ValueMatcher::parse(&json!({"regexx": "a"})).is_err());
        assert!(ValueMatcher::parse(&json!({"regex": "("})).is_err());
        assert!(ValueMatcher::parse(&json!({"in": "a"})).is_err());
        assert!(ValueMatcher::parse(&json!({"lt": "a"})).is_err());
        assert!(ValueMatcher::parse(&json!({"exists": "yes"})).is_err());
        assert!(ValueMatcher::parse(&json!({})).is_err());
        assert!(ValueMatcher::parse(&json!({"regex": "a{1000}{1000}"})).is_err());
        let mut deep = json!("x");
        for _ in 0..10 {
            deep = json!({ "any": deep });
        }
        assert!(ValueMatcher::parse(&deep).is_err());
        assert!(ArgsMatcher::parse(&json!(["a"])).is_err());
        assert!(ArgsMatcher::parse(&json!({"a..b": 1})).is_err());
    }

    #[test]
    fn paths_and_args() {
        let args = json!({
            "table": "users",
            "options": {"force": true, "tags": ["a", "b"]},
            "items": [{"id": 7}],
            "dotted.key": "literal",
            "nothing": null
        });
        let m = ArgsMatcher::parse(&json!({
            "table": {"in": ["users", "payments"]},
            "options.force": true,
            "options.tags.1": "b",
            "items.0.id": {"gte": 7},
            "dotted.key": "literal",
            "nothing": {"exists": false},
            "absent.deep": {"exists": false}
        }))
        .unwrap();
        assert!(m.matches(&args));
        assert!(!ArgsMatcher::parse(&json!({"table": "orders"})).unwrap().matches(&args));
        assert!(!ArgsMatcher::parse(&json!({"options.tags.x": {"exists": true}})).unwrap().matches(&args));
        assert!(ArgsMatcher::parse(&Value::Null).unwrap().is_empty());
        assert_eq!(ArgsMatcher::parse(&json!({"a": {"regex": "x", "any": {"regex": "y"}}})).unwrap().regex_count(), 2);
    }
}
