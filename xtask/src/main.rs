//! xtask: repository maintenance tasks (structural checks + spec derivation).

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    match arg.as_str() {
        "derive" => derive(),
        "check" => check(),
        _ => {
            println!("usage: cargo run -p xtask -- [derive|check]");
            Ok(())
        }
    }
}

/// Emit the public JSON schemas from the Rust types. The types are the one
/// semantic authority; the schemas are derived artifacts. CI runs this and
/// then fails on a dirty tree, so schema/code drift cannot merge.
fn derive() -> anyhow::Result<()> {
    let specs: [(&str, &str, serde_json::Value); 2] = [
        (
            "spec/extension-manifest.schema.json",
            "urn:politeia:extension-manifest:v1",
            serde_json::to_value(schemars::schema_for!(politeia_sdk::ExtensionManifest))?,
        ),
        (
            "spec/semantic-operation.schema.json",
            "urn:politeia:semantic-operation:v1",
            serde_json::to_value(schemars::schema_for!(
                politeia_runtime::OperationIntent
            ))?,
        ),
    ];
    for (path, urn, mut value) in specs {
        let obj = value.as_object_mut().context("schema root is an object")?;
        // The published URN stays stable regardless of schemars' own titling.
        obj.insert("$id".to_string(), serde_json::Value::String(urn.to_string()));
        obj.insert(
            "$comment".to_string(),
            serde_json::Value::String(
                "Derived from the Rust types by `cargo run -p xtask -- derive`. Do not hand-edit."
                    .to_string(),
            ),
        );
        let mut text = serde_json::to_string_pretty(&value)?;
        text.push('\n');
        std::fs::write(path, text)?;
        println!("derived {path}");
    }
    Ok(())
}

/// Structural invariants that do not need a type system to check.
fn check() -> anyhow::Result<()> {
    for required in [
        "docs/02-CONSTITUTION.md",
        "docs/03-ONTOLOGY.md",
        "docs/04-KERNEL_CONTRACT.md",
        "docs/18-FIRST_VERTICAL_SLICE.md",
    ] {
        anyhow::ensure!(std::path::Path::new(required).exists(), "missing {required}");
    }
    println!("starter structural checks passed");
    Ok(())
}
