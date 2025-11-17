//! Comprehensive test of all 121 PSF protocol files
//!
//! This test loads every single PSF file in the protocols/ directory
//! and reports which ones parse successfully vs which have errors

use nooshdaroo::psf::PsfInterpreter;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_all_121_psf_files() {
    println!("\n=== TESTING ALL 121 PSF PROTOCOL FILES ===\n");

    // Find all PSF files
    let psf_files = find_all_psf_files("protocols");

    println!("Found {} PSF files\n", psf_files.len());

    let mut results: HashMap<String, Result<String, String>> = HashMap::new();
    let mut success_count = 0;
    let mut error_types: HashMap<String, Vec<String>> = HashMap::new();

    for psf_path in &psf_files {
        let protocol_name = psf_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        match PsfInterpreter::load_from_file(psf_path) {
            Ok(_interp) => {
                results.insert(protocol_name.to_string(), Ok("SUCCESS".to_string()));
                success_count += 1;
            }
            Err(e) => {
                let error_msg = e.to_string();
                let error_category = categorize_error(&error_msg);

                error_types.entry(error_category.clone())
                    .or_insert_with(Vec::new)
                    .push(protocol_name.to_string());

                results.insert(protocol_name.to_string(), Err(error_msg));
            }
        }
    }

    // Print summary
    println!("=== RESULTS SUMMARY ===");
    println!("Total: {}", psf_files.len());
    println!("✅ Success: {}", success_count);
    println!("❌ Failed: {}\n", psf_files.len() - success_count);

    // Print error categories
    if !error_types.is_empty() {
        println!("=== ERROR CATEGORIES ===\n");
        for (category, protocols) in error_types.iter() {
            println!("{}: {} protocols", category, protocols.len());
            for protocol in protocols {
                println!("  - {}", protocol);
            }
            println!();
        }
    }

    // Print detailed failures
    println!("=== DETAILED FAILURES ===\n");
    for (name, result) in &results {
        if let Err(e) = result {
            println!("❌ {}", name);
            println!("   Error: {}\n", e);
        }
    }

    // Print successes
    println!("=== SUCCESSFUL PROTOCOLS ({}) ===\n", success_count);
    for (name, result) in &results {
        if result.is_ok() {
            println!("✅ {}", name);
        }
    }

    println!("\n=== TEST COMPLETE ===");
    println!("Success rate: {:.1}%", (success_count as f64 / psf_files.len() as f64) * 100.0);
}

fn find_all_psf_files(dir: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(find_all_psf_files(path.to_str().unwrap()));
            } else if path.extension().and_then(|s| s.to_str()) == Some("psf") {
                files.push(path);
            }
        }
    }

    files.sort();
    files
}

fn categorize_error(error: &str) -> String {
    if error.contains("Unexpected character: '-'") {
        "Dash in comments/identifiers".to_string()
    } else if error.contains("Unexpected character: '''") {
        "Single quote strings".to_string()
    } else if error.contains("Unknown semantic type") {
        "Unsupported semantic type".to_string()
    } else if error.contains("Expected") {
        "Syntax parsing error".to_string()
    } else {
        "Other error".to_string()
    }
}
