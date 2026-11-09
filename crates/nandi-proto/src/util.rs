//! Small JSON helpers shared by the protocol modules.

use serde_json::{Map, Value};

/// String field of an object, if present and a string.
pub(crate) fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// First present field among `keys` (camelCase / snake_case aliases).
pub(crate) fn get_any<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|k| v.get(*k)).filter(|x| !x.is_null())
}

/// Same as [`get_any`] but mutable.
pub(crate) fn get_any_mut<'a>(v: &'a mut Value, keys: &[&str]) -> Option<&'a mut Value> {
    let key = keys.iter().find(|k| v.get(**k).is_some_and(|x| !x.is_null()))?;
    v.get_mut(*key)
}

/// Unsigned integer field, 0 when missing.
pub(crate) fn u(v: &Value, path: &[&str]) -> u64 {
    let mut cur = v;
    for k in path {
        match cur.get(*k) {
            Some(x) => cur = x,
            None => return 0,
        }
    }
    cur.as_u64().unwrap_or(0)
}

/// Unsigned integer field, `None` when missing.
pub(crate) fn u_opt(v: &Value, path: &[&str]) -> Option<u64> {
    let mut cur = v;
    for k in path {
        cur = cur.get(*k)?;
    }
    cur.as_u64()
}

/// Array field or an empty slice.
pub(crate) fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// Append `text` to `out`, separated by a newline.
pub(crate) fn push_text(out: &mut String, text: &str) {
    if text.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(text);
}

/// Parse tool-call arguments delivered as a JSON string. Empty means `{}`;
/// unparseable input is kept verbatim as `{"_raw": "..."}` so nothing is lost.
pub(crate) fn parse_args(raw: &str) -> Value {
    let t = raw.trim();
    if t.is_empty() {
        return Value::Object(Map::new());
    }
    serde_json::from_str(t).unwrap_or_else(|_| {
        let mut m = Map::new();
        m.insert("_raw".into(), Value::String(raw.to_string()));
        Value::Object(m)
    })
}

/// Arguments that may be either a JSON string or an inline JSON value.
pub(crate) fn args_value(v: Option<&Value>) -> Value {
    match v {
        Some(Value::String(raw)) => parse_args(raw),
        Some(Value::Null) | None => Value::Object(Map::new()),
        Some(other) => other.clone(),
    }
}

/// Text for a value that may be a string or structured JSON.
pub(crate) fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Rewrite every string leaf (values only, not keys). Returns true when any
/// string changed.
pub(crate) fn rewrite_string_leaves(v: &mut Value, f: &mut dyn FnMut(&str) -> Option<String>) -> bool {
    match v {
        Value::String(s) => match f(s) {
            Some(new) if new != *s => {
                *s = new;
                true
            }
            _ => false,
        },
        Value::Array(items) => {
            let mut changed = false;
            for item in items {
                changed |= rewrite_string_leaves(item, f);
            }
            changed
        }
        Value::Object(map) => {
            let mut changed = false;
            for (_, item) in map.iter_mut() {
                changed |= rewrite_string_leaves(item, f);
            }
            changed
        }
        _ => false,
    }
}

/// Apply `f` to a string field in place. Returns true when it changed.
pub(crate) fn rewrite_field(obj: &mut Value, key: &str, f: &mut dyn FnMut(&str) -> Option<String>) -> bool {
    if let Some(Value::String(s)) = obj.get_mut(key)
        && let Some(new) = f(s)
        && new != *s
    {
        *s = new;
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_args_variants() {
        assert_eq!(parse_args(""), json!({}));
        assert_eq!(parse_args("{\"a\":1}"), json!({"a": 1}));
        assert_eq!(parse_args("{\"a\":"), json!({"_raw": "{\"a\":"}));
        assert_eq!(args_value(Some(&json!({"x": 2}))), json!({"x": 2}));
        assert_eq!(args_value(None), json!({}));
    }

    #[test]
    fn rewrites_leaves() {
        let mut v = json!({"a": ["x", {"b": "y"}], "n": 1});
        let changed = rewrite_string_leaves(&mut v, &mut |s| (s == "y").then(|| "Y".to_string()));
        assert!(changed);
        assert_eq!(v, json!({"a": ["x", {"b": "Y"}], "n": 1}));
        assert_eq!(u(&json!({"a": {"b": 3}}), &["a", "b"]), 3);
        assert_eq!(u_opt(&json!({}), &["a"]), None);
    }
}
