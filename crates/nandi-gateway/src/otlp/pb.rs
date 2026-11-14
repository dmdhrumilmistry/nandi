//! OTLP protobuf encoding, derived from the OTLP JSON encoding.
//!
//! nandi builds every OTLP request as JSON ([`super::model`]). For
//! `http/protobuf` the JSON is walked against a table of the OTLP message
//! fields it uses (numbers and types from the `opentelemetry-proto`
//! definitions) and written in protobuf wire format. This keeps one model
//! and avoids a protobuf code generator and its dependencies.
//!
//! JSON follows the OTLP JSON rules: lowerCamelCase field names, trace and
//! span ids as hex, 64-bit integers as strings, enums as numbers.

use serde_json::Value;

/// Field types used by OTLP.
#[derive(Clone, Copy)]
enum T {
    Msg(&'static [F]),
    Str,
    Bool,
    /// `int64`, `uint32` and enums: varint.
    Varint,
    /// `fixed64` (timestamps, counts).
    Fixed64,
    /// `sfixed64` (`asInt`).
    Sfixed64,
    /// `fixed32` (flags).
    Fixed32,
    Double,
    /// `bytes` written as hex in JSON (trace and span ids).
    Hex,
}

/// A message field: JSON name, field number, type.
struct F(&'static str, u32, T);

use T::*;

// nandi writes arrays and maps as JSON strings, so `arrayValue` (5) and
// `kvlistValue` (6) are not needed (and would make the tables recursive).
const ANY: &[F] =
    &[F("stringValue", 1, Str), F("boolValue", 2, Bool), F("intValue", 3, Varint), F("doubleValue", 4, Double)];
const KV: &[F] = &[F("key", 1, Str), F("value", 2, Msg(ANY))];
const RESOURCE: &[F] = &[F("attributes", 1, Msg(KV)), F("droppedAttributesCount", 2, Varint)];
const SCOPE: &[F] =
    &[F("name", 1, Str), F("version", 2, Str), F("attributes", 3, Msg(KV)), F("droppedAttributesCount", 4, Varint)];

// opentelemetry/proto/trace/v1/trace.proto
const STATUS: &[F] = &[F("message", 2, Str), F("code", 3, Varint)];
const SPAN: &[F] = &[
    F("traceId", 1, Hex),
    F("spanId", 2, Hex),
    F("traceState", 3, Str),
    F("parentSpanId", 4, Hex),
    F("name", 5, Str),
    F("kind", 6, Varint),
    F("startTimeUnixNano", 7, Fixed64),
    F("endTimeUnixNano", 8, Fixed64),
    F("attributes", 9, Msg(KV)),
    F("droppedAttributesCount", 10, Varint),
    F("status", 15, Msg(STATUS)),
    F("flags", 16, Fixed32),
];
const SCOPE_SPANS: &[F] = &[F("scope", 1, Msg(SCOPE)), F("spans", 2, Msg(SPAN)), F("schemaUrl", 3, Str)];
const RESOURCE_SPANS: &[F] =
    &[F("resource", 1, Msg(RESOURCE)), F("scopeSpans", 2, Msg(SCOPE_SPANS)), F("schemaUrl", 3, Str)];
/// `ExportTraceServiceRequest`.
const TRACES: &[F] = &[F("resourceSpans", 1, Msg(RESOURCE_SPANS))];

// opentelemetry/proto/logs/v1/logs.proto
const LOG_RECORD: &[F] = &[
    F("timeUnixNano", 1, Fixed64),
    F("severityNumber", 2, Varint),
    F("severityText", 3, Str),
    F("body", 5, Msg(ANY)),
    F("attributes", 6, Msg(KV)),
    F("droppedAttributesCount", 7, Varint),
    F("flags", 8, Fixed32),
    F("traceId", 9, Hex),
    F("spanId", 10, Hex),
    F("observedTimeUnixNano", 11, Fixed64),
    F("eventName", 12, Str),
];
const SCOPE_LOGS: &[F] = &[F("scope", 1, Msg(SCOPE)), F("logRecords", 2, Msg(LOG_RECORD)), F("schemaUrl", 3, Str)];
const RESOURCE_LOGS: &[F] =
    &[F("resource", 1, Msg(RESOURCE)), F("scopeLogs", 2, Msg(SCOPE_LOGS)), F("schemaUrl", 3, Str)];
/// `ExportLogsServiceRequest`.
const LOGS: &[F] = &[F("resourceLogs", 1, Msg(RESOURCE_LOGS))];

// opentelemetry/proto/metrics/v1/metrics.proto
const NUMBER_POINT: &[F] = &[
    F("startTimeUnixNano", 2, Fixed64),
    F("timeUnixNano", 3, Fixed64),
    F("asDouble", 4, Double),
    F("asInt", 6, Sfixed64),
    F("attributes", 7, Msg(KV)),
    F("flags", 8, Varint),
];
const HISTOGRAM_POINT: &[F] = &[
    F("startTimeUnixNano", 2, Fixed64),
    F("timeUnixNano", 3, Fixed64),
    F("count", 4, Fixed64),
    F("sum", 5, Double),
    F("bucketCounts", 6, Fixed64),
    F("explicitBounds", 7, Double),
    F("attributes", 9, Msg(KV)),
    F("flags", 10, Varint),
    F("min", 11, Double),
    F("max", 12, Double),
];
const GAUGE: &[F] = &[F("dataPoints", 1, Msg(NUMBER_POINT))];
const SUM: &[F] =
    &[F("dataPoints", 1, Msg(NUMBER_POINT)), F("aggregationTemporality", 2, Varint), F("isMonotonic", 3, Bool)];
const HISTOGRAM: &[F] = &[F("dataPoints", 1, Msg(HISTOGRAM_POINT)), F("aggregationTemporality", 2, Varint)];
const METRIC: &[F] = &[
    F("name", 1, Str),
    F("description", 2, Str),
    F("unit", 3, Str),
    F("gauge", 5, Msg(GAUGE)),
    F("sum", 7, Msg(SUM)),
    F("histogram", 9, Msg(HISTOGRAM)),
];
const SCOPE_METRICS: &[F] = &[F("scope", 1, Msg(SCOPE)), F("metrics", 2, Msg(METRIC)), F("schemaUrl", 3, Str)];
const RESOURCE_METRICS: &[F] =
    &[F("resource", 1, Msg(RESOURCE)), F("scopeMetrics", 2, Msg(SCOPE_METRICS)), F("schemaUrl", 3, Str)];
/// `ExportMetricsServiceRequest`.
const METRICS: &[F] = &[F("resourceMetrics", 1, Msg(RESOURCE_METRICS))];

/// Which OTLP export request a JSON document is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Traces,
    Logs,
    Metrics,
}

/// Encode an OTLP JSON export request as protobuf.
pub fn encode(kind: Request, doc: &Value) -> Result<Vec<u8>, String> {
    let schema = match kind {
        Request::Traces => TRACES,
        Request::Logs => LOGS,
        Request::Metrics => METRICS,
    };
    let mut out = Vec::with_capacity(1024);
    message(schema, doc, &mut out)?;
    Ok(out)
}

fn message(schema: &[F], v: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    let obj = v.as_object().ok_or_else(|| format!("expected an object, got {v}"))?;
    // Fields in schema order, so output does not depend on JSON key order.
    for (key, _) in obj {
        if !schema.iter().any(|f| f.0 == key) {
            return Err(format!("unknown OTLP field {key}"));
        }
    }
    for F(name, num, ty) in schema {
        let Some(val) = obj.get(*name) else { continue };
        if val.is_null() {
            continue;
        }
        match val {
            Value::Array(items) => match ty {
                // Repeated scalars are packed.
                Fixed64 | Sfixed64 | Double | Varint | Fixed32 | Bool => {
                    let mut packed = Vec::with_capacity(items.len() * 8);
                    for item in items {
                        scalar(*ty, item, &mut packed)?;
                    }
                    key(*num, 2, out);
                    varint(packed.len() as u64, out);
                    out.extend_from_slice(&packed);
                }
                _ => {
                    for item in items {
                        field(*num, *ty, item, out)?;
                    }
                }
            },
            _ => field(*num, *ty, val, out)?,
        }
    }
    Ok(())
}

fn field(num: u32, ty: T, v: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    match ty {
        Msg(schema) => {
            let mut inner = Vec::new();
            message(schema, v, &mut inner)?;
            key(num, 2, out);
            varint(inner.len() as u64, out);
            out.extend_from_slice(&inner);
        }
        Str => {
            let s = v.as_str().ok_or_else(|| format!("expected a string, got {v}"))?;
            key(num, 2, out);
            varint(s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Hex => {
            let s = v.as_str().ok_or_else(|| format!("expected hex, got {v}"))?;
            let bytes = hex::decode(s).map_err(|e| format!("bad id {s}: {e}"))?;
            key(num, 2, out);
            varint(bytes.len() as u64, out);
            out.extend_from_slice(&bytes);
        }
        Varint | Bool => {
            key(num, 0, out);
            scalar(ty, v, out)?;
        }
        Fixed64 | Sfixed64 | Double => {
            key(num, 1, out);
            scalar(ty, v, out)?;
        }
        Fixed32 => {
            key(num, 5, out);
            scalar(ty, v, out)?;
        }
    }
    Ok(())
}

/// A scalar without its key (also the packed element encoding).
fn scalar(ty: T, v: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    match ty {
        Bool => varint(u64::from(v.as_bool().ok_or_else(|| format!("expected a bool, got {v}"))?), out),
        // Negative int64 values are ten-byte varints of their two's complement.
        Varint => varint(int(v)? as u64, out),
        Fixed64 => out.extend_from_slice(&(uint(v)?).to_le_bytes()),
        Sfixed64 => out.extend_from_slice(&int(v)?.to_le_bytes()),
        Fixed32 => out.extend_from_slice(&(uint(v)? as u32).to_le_bytes()),
        Double => {
            let f = v.as_f64().ok_or_else(|| format!("expected a number, got {v}"))?;
            out.extend_from_slice(&f.to_le_bytes());
        }
        _ => return Err("not a scalar".into()),
    }
    Ok(())
}

fn int(v: &Value) -> Result<i64, String> {
    match v {
        Value::Number(n) => n.as_i64().ok_or_else(|| format!("expected an integer, got {n}")),
        Value::String(s) => s.parse().map_err(|_| format!("expected an integer, got {s}")),
        _ => Err(format!("expected an integer, got {v}")),
    }
}

fn uint(v: &Value) -> Result<u64, String> {
    match v {
        Value::Number(n) => n.as_u64().ok_or_else(|| format!("expected an unsigned integer, got {n}")),
        Value::String(s) => s.parse().map_err(|_| format!("expected an unsigned integer, got {s}")),
        _ => Err(format!("expected an unsigned integer, got {v}")),
    }
}

fn key(num: u32, wire: u8, out: &mut Vec<u8>) {
    varint((u64::from(num) << 3) | u64::from(wire), out);
}

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wire_format_of_small_messages() {
        // KeyValue{key:"a", value:{intValue:"150"}}: 0a 01 61 12 03 18 96 01
        let mut out = Vec::new();
        message(KV, &json!({"key": "a", "value": {"intValue": "150"}}), &mut out).unwrap();
        assert_eq!(out, [0x0a, 0x01, b'a', 0x12, 0x03, 0x18, 0x96, 0x01]);
        // Packed fixed64 and doubles.
        let mut out = Vec::new();
        message(HISTOGRAM_POINT, &json!({"bucketCounts": ["1", "2"], "explicitBounds": [0.5]}), &mut out).unwrap();
        let mut want = vec![0x32, 16];
        want.extend_from_slice(&1u64.to_le_bytes());
        want.extend_from_slice(&2u64.to_le_bytes());
        want.extend_from_slice(&[0x3a, 8]);
        want.extend_from_slice(&0.5f64.to_le_bytes());
        assert_eq!(out, want);
        // Hex ids become bytes; negative ints are ten-byte varints.
        let mut out = Vec::new();
        message(SPAN, &json!({"spanId": "00000000000000ff", "kind": 1}), &mut out).unwrap();
        assert_eq!(out, [0x12, 8, 0, 0, 0, 0, 0, 0, 0, 0xff, 0x30, 1]);
        let mut out = Vec::new();
        message(ANY, &json!({"intValue": "-1"}), &mut out).unwrap();
        assert_eq!(out, [0x18, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
    }

    #[test]
    fn unknown_fields_are_errors() {
        assert!(encode(Request::Traces, &json!({"resourceSpanz": []})).is_err());
    }
}
