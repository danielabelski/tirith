use tirith_core::receipt::Receipt;

pub fn last(json: bool) -> i32 {
    match Receipt::list() {
        Ok(receipts) => {
            if let Some(r) = receipts.first() {
                if json {
                    // Public DTO: credential-bearing URL userinfo is redacted
                    // and local-machine metadata (cwd) omitted (repo-0415).
                    if serde_json::to_writer_pretty(std::io::stdout().lock(), &r.public_view())
                        .is_err()
                    {
                        eprintln!("tirith: failed to write JSON output");
                        return 1;
                    }
                    println!();
                } else {
                    print_receipt(r);
                }
                0
            } else {
                eprintln!("tirith: no receipts found");
                1
            }
        }
        Err(e) => {
            eprintln!("tirith: {e}");
            1
        }
    }
}

pub fn list(json: bool) -> i32 {
    match Receipt::list() {
        Ok(receipts) => {
            if json {
                let public: Vec<_> = receipts.iter().map(|r| r.public_view()).collect();
                if serde_json::to_writer_pretty(std::io::stdout().lock(), &public).is_err() {
                    eprintln!("tirith: failed to write JSON output");
                    return 1;
                }
                println!();
            } else if receipts.is_empty() {
                eprintln!("tirith: no receipts found");
            } else {
                for r in &receipts {
                    eprintln!(
                        "  {} {} ({} bytes) {}",
                        tirith_core::receipt::short_hash(&r.sha256),
                        super::sanitize_for_human_output(&r.url, false),
                        r.size,
                        r.timestamp
                    );
                }
            }
            0
        }
        Err(e) => {
            eprintln!("tirith: {e}");
            1
        }
    }
}

pub fn verify(sha256: &str, json: bool) -> i32 {
    match Receipt::load(sha256) {
        Ok(r) => match r.verify() {
            Ok(valid) => {
                if json {
                    let out = serde_json::json!({
                        "sha256": sha256,
                        "valid": valid,
                        "url": r.url,
                    });
                    if serde_json::to_writer_pretty(std::io::stdout().lock(), &out).is_err() {
                        eprintln!("tirith: failed to write JSON output");
                        return 1;
                    }
                    println!();
                } else if valid {
                    eprintln!(
                        "tirith: receipt {} verified OK",
                        tirith_core::receipt::short_hash(sha256)
                    );
                } else {
                    eprintln!(
                        "tirith: receipt {} FAILED verification",
                        tirith_core::receipt::short_hash(sha256)
                    );
                }
                if valid {
                    0
                } else {
                    1
                }
            }
            Err(e) => {
                eprintln!("tirith: verify failed: {e}");
                1
            }
        },
        Err(e) => {
            eprintln!("tirith: {e}");
            1
        }
    }
}

fn print_receipt(r: &Receipt) {
    eprintln!("tirith: receipt");
    eprintln!(
        "  url:       {}",
        super::sanitize_for_human_output(&r.url, false)
    );
    if let Some(ref fu) = r.final_url {
        eprintln!(
            "  final_url: {}",
            super::sanitize_for_human_output(fu, false)
        );
    }
    eprintln!("  sha256:    {}", r.sha256);
    eprintln!("  size:      {} bytes", r.size);
    eprintln!(
        "  analyzed:  {}",
        super::sanitize_for_human_output(&r.analysis_method, false)
    );
    eprintln!(
        "  privilege: {}",
        super::sanitize_for_human_output(&r.privilege, false)
    );
    eprintln!("  when:      {}", r.timestamp);
    if !r.domains_referenced.is_empty() {
        eprintln!(
            "  domains:   {}",
            super::sanitize_for_human_output(&r.domains_referenced.join(", "), false)
        );
    }
}
