//! Hook offset tables keyed by swtor.exe SHA256, plus the report the DLL
//! sends back describing which hooks it managed to install.
//!
//! The same JSON schema is used for the bundled `offsets.json`, the document
//! served by the hosted offsets server, and the cached copy of that document.

// The DLL build (cdylib) only uses the HookReport types; the table side is
// used by the service binary. Silence dead-code noise in whichever is built.
#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Names of the offsets the DLL understands.
pub mod names {
    pub const CHAT_RECV: &str = "chat_recv";
    pub const ROLL_HANDLER: &str = "roll_handler";
    pub const CMD_DISPATCH: &str = "cmd_dispatch";
    pub const GLOBAL_PTR: &str = "global_ptr";
    pub const CONTEXT_VTABLE: &str = "context_vtable";
    pub const MANAGER_VTABLE: &str = "manager_vtable";
    pub const FRIENDS_LIST: &str = "friends_list";
}

/// Offsets for one specific build of swtor.exe.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VersionOffsets {
    /// Lowercase hex SHA256 of swtor.exe.
    pub sha256: String,
    #[serde(default)]
    pub label: Option<String>,
    /// Offset name -> RVA. Accepts hex strings (`"0x5220b0"`) or numbers.
    #[serde(default, deserialize_with = "deserialize_rva_map")]
    pub offsets: BTreeMap<String, u64>,
}

/// A set of builds and their offsets.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OffsetTable {
    #[serde(default)]
    pub versions: Vec<VersionOffsets>,
}

/// The offsets file shipped with the client. Single source of truth for both crates.
pub const BUNDLED_OFFSETS_JSON: &str = include_str!("../../../ChaTOR/src-tauri/offsets.json");

/// Accepts an RVA written either as a JSON number or as a string such as
/// `"0x5220b0"` (hex, with or without the `0x` prefix) or `"5382320"` (decimal).
fn deserialize_rva_map<'de, D>(deserializer: D) -> Result<BTreeMap<String, u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Rva {
        Number(u64),
        Text(String),
    }

    let raw: BTreeMap<String, Rva> = BTreeMap::deserialize(deserializer)?;
    raw.into_iter()
        .map(|(name, rva)| {
            let value = match rva {
                Rva::Number(n) => n,
                Rva::Text(s) => parse_rva(&s)
                    .ok_or_else(|| D::Error::custom(format!("invalid RVA {:?} for {}", s, name)))?,
            };
            Ok((name, value))
        })
        .collect()
}

fn parse_rva(text: &str) -> Option<u64> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if t.chars().all(|c| c.is_ascii_digit()) && !t.is_empty() {
        t.parse().ok()
    } else {
        u64::from_str_radix(t, 16).ok()
    }
}

impl OffsetTable {
    pub fn from_json(contents: &str) -> Result<OffsetTable, String> {
        serde_json::from_str(contents).map_err(|e| e.to_string())
    }

    /// The table compiled into the binary.
    pub fn bundled() -> OffsetTable {
        OffsetTable::from_json(BUNDLED_OFFSETS_JSON)
            .expect("bundled offsets.json must parse")
    }

    /// Finds the entry for a given executable hash (case-insensitive).
    pub fn find(&self, sha256_hex: &str) -> Option<&VersionOffsets> {
        let wanted = sha256_hex.trim().to_ascii_lowercase();
        self.versions
            .iter()
            .find(|v| v.sha256.trim().to_ascii_lowercase() == wanted)
    }

    /// Returns a table containing `primary` entries first, then any entries of
    /// `fallback` whose hash is not already present.
    pub fn merged(primary: &OffsetTable, fallback: &OffsetTable) -> OffsetTable {
        let mut versions = primary.versions.clone();
        for v in &fallback.versions {
            if versions
                .iter()
                .all(|p| !p.sha256.eq_ignore_ascii_case(&v.sha256))
            {
                versions.push(v.clone());
            }
        }
        OffsetTable { versions }
    }
}

/// Where a hook's address came from.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OffsetSource {
    /// Found at runtime by scanning the loaded image.
    Dynamic,
    /// Taken from the offset table for this executable hash.
    Table,
    /// No address was available.
    None,
}

/// Status of a single hook after the DLL tried to install it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HookStatus {
    pub name: String,
    pub rva: Option<u64>,
    pub source: OffsetSource,
    pub installed: bool,
    /// Human readable notes: scan details, mismatches, errors.
    #[serde(default)]
    pub detail: Option<String>,
}

/// What the DLL reports back after `InstallHooks`.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HookReport {
    pub sha256: Option<String>,
    pub dynamic_lookup: bool,
    pub hooks: Vec<HookStatus>,
}

impl HookReport {
    pub fn installed_count(&self) -> usize {
        self.hooks.iter().filter(|h| h.installed).count()
    }

    pub fn summary(&self) -> String {
        self.hooks
            .iter()
            .map(|h| {
                format!(
                    "{}={}{}",
                    h.name,
                    match h.rva {
                        Some(r) => format!("0x{:x}", r),
                        None => "none".to_string(),
                    },
                    if h.installed { "(ok)" } else { "(FAILED)" }
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_json_parses_hex_rvas() {
        let table = OffsetTable::bundled();
        assert!(table.versions.len() >= 3);
        let oct = table
            .find("0F32B9D9562DAFCE89BE662014615E0CC288F042A3FCFBBD8C38271ABCD690F5")
            .expect("2026-10-16 entry present (lookup is case-insensitive)");
        assert_eq!(oct.offsets[names::CHAT_RECV], 0x5220b0);
        assert_eq!(oct.offsets[names::CMD_DISPATCH], 0x3e25b0);
        assert_eq!(oct.offsets[names::ROLL_HANDLER], 0xe56780);
        assert!(!oct.offsets.contains_key(names::GLOBAL_PTR));
    }

    #[test]
    fn rva_values_accept_numbers_and_strings() {
        let t = OffsetTable::from_json(
            r#"{"versions":[{"sha256":"ab","offsets":{"a":"0x10","b":16,"c":"10","d":"ff"}}]}"#,
        )
        .unwrap();
        let o = &t.versions[0].offsets;
        assert_eq!(o["a"], 0x10);
        assert_eq!(o["b"], 16);
        assert_eq!(o["c"], 10);
        assert_eq!(o["d"], 0xff);
        assert!(OffsetTable::from_json(r#"{"versions":[{"sha256":"ab","offsets":{"a":"zz"}}]}"#).is_err());
    }

    #[test]
    fn merged_prefers_primary() {
        let primary = OffsetTable::from_json(r#"{"versions":[{"sha256":"AA","offsets":{"x":1}}]}"#).unwrap();
        let fallback = OffsetTable::from_json(
            r#"{"versions":[{"sha256":"aa","offsets":{"x":2}},{"sha256":"bb","offsets":{"x":3}}]}"#,
        )
        .unwrap();
        let m = OffsetTable::merged(&primary, &fallback);
        assert_eq!(m.versions.len(), 2);
        assert_eq!(m.find("aa").unwrap().offsets["x"], 1);
        assert_eq!(m.find("bb").unwrap().offsets["x"], 3);
    }
}
