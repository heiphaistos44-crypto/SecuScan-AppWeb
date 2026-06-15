//! scanner_web.rs — Orchestrateur de scan pour le web (sans Tauri).
//! Adapté de engine/scanner.rs (desktop v1.0.5) : walk d'un arbre de fichiers,
//! dispatch vers les parsers, heuristiques de faux positifs. Pas d'events ni de
//! cancellation (le timeout HTTP + le sémaphore gèrent la charge côté serveur).

use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use walkdir::{DirEntry, WalkDir};

use crate::models::{ScanConfig, ScanResult, Vulnerability};
use crate::parsers::{binary, config, sast, script};

// ─── Skip rules ───────────────────────────────────────────────────────────────

fn should_skip(entry: &DirEntry, cfg: &ScanConfig) -> bool {
    let name = entry.file_name().to_string_lossy();
    if cfg.skip_git_dirs && (name == ".git" || name == ".svn") {
        return true;
    }
    if cfg.skip_node_modules && name == "node_modules" {
        return true;
    }
    if matches!(name.as_ref(), "target" | "dist" | "build" | ".idea" | ".vs" | "__pycache__" |
                               "vendor"  | ".cargo" | "Pods"  | "Carthage" | "Packages" |
                               ".gradle" | ".m2"    | "bower_components" | "jspm_packages") {
        return true;
    }
    false
}

fn file_extension(path: &Path) -> &str {
    path.extension().and_then(|e| e.to_str()).unwrap_or("")
}

fn read_file_capped(path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::with_capacity(max_bytes.min(4096));
    reader.by_ref().take(max_bytes as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

const MAX_REGEX_BYTES: usize = 512 * 1024;

#[inline]
fn cap(data: &[u8]) -> &[u8] {
    if data.len() > MAX_REGEX_BYTES { &data[..MAX_REGEX_BYTES] } else { data }
}

// ─── Dispatch vers le bon parser ─────────────────────────────────────────────

fn dispatch(path: &Path, data: &[u8], cfg: &ScanConfig) -> Vec<Vulnerability> {
    let ext = file_extension(path).to_lowercase();
    let ext = ext.as_str();

    if sast::handles_extension(ext) {
        return sast::scan_source(path, cap(data));
    }
    if script::handles_extension(ext) {
        return script::scan_script(path, cap(data));
    }
    if config::handles_extension(ext) {
        return config::scan_config(path, cap(data));
    }
    if cfg.scan_executables && binary::handles_extension(ext) {
        return binary::scan_binary(path, data);
    }

    let skip_fallback = matches!(ext, "txt" | "log" | "csv" | "md" | "rst" | "nfo" |
                                       "rtf" | "out" | "tmp" | "dat" | "cache" |
                                       "lock" | "sum" | "manifest");
    if !skip_fallback && data.iter().filter(|&&b| b == 0).count() < data.len() / 20 {
        const FALLBACK_CAP: usize = 512 * 1024;
        let slice = if data.len() > FALLBACK_CAP { &data[..FALLBACK_CAP] } else { data };
        return config::scan_config(path, slice);
    }

    vec![]
}

/// Dispatch avec timeout dur de 10 s et cancel flag (parser bloqué = fichier sauté).
fn dispatch_timed(path: PathBuf, data: Vec<u8>, cfg: ScanConfig) -> Vec<Vulnerability> {
    use std::sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc};
    use std::time::Duration;

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();
    let (tx, rx) = mpsc::channel::<Vec<Vulnerability>>();

    std::thread::spawn(move || {
        if cancel_clone.load(Ordering::Relaxed) { return; }
        let result = dispatch(&path, &data, &cfg);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(vulns) => vulns,
        Err(_) => {
            cancel.store(true, Ordering::Relaxed);
            log::warn!("File scan timed out — skipped");
            vec![]
        }
    }
}

// ─── Entrée publique : scan d'un arbre de fichiers ────────────────────────────
//
// `display_root` : préfixe affiché dans le rapport (les chemins sont rendus
// relatifs à ce préfixe pour ne jamais exposer l'arborescence temp du serveur).

pub fn scan_tree(root: &Path, display_root: &str, cfg: ScanConfig) -> ScanResult {
    let entries: Vec<PathBuf> = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !should_skip(e, &cfg))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    let total = entries.len();
    let mut result = ScanResult::new(display_root.to_string(), total);
    let max_bytes = (cfg.max_file_size_mb * 1024.0 * 1024.0) as usize;

    let scan_results: Vec<Vec<Vulnerability>> = entries
        .par_iter()
        .map(|path| {
            match read_file_capped(path, max_bytes) {
                Ok(data) => {
                    let mut vulns = dispatch_timed(path.clone(), data, cfg.clone());
                    // Rend le chemin relatif au root temp → affiche le chemin projet
                    let rel = path.strip_prefix(root).unwrap_or(path);
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    for v in &mut vulns {
                        v.file_path = rel_str.clone();
                    }
                    vulns
                }
                Err(e) => {
                    log::warn!("Scan IO error: {}: {e}", path.display());
                    vec![]
                }
            }
        })
        .collect();

    for vulns in scan_results {
        result.vulnerabilities.extend(vulns);
        result.scanned_files += 1;
    }

    result.vulnerabilities.sort_by(|a, b| b.severity.score().cmp(&a.severity.score()));
    apply_fp_hints(&mut result.vulnerabilities);
    result.finalize();
    result
}

/// Scan d'un fichier unique uploadé (déjà écrit dans `path`).
pub fn scan_single(path: &Path, display_name: &str, cfg: ScanConfig) -> ScanResult {
    let mut result = ScanResult::new(display_name.to_string(), 1);
    let max_bytes = (cfg.max_file_size_mb * 1024.0 * 1024.0) as usize;

    if let Ok(data) = read_file_capped(path, max_bytes) {
        let mut vulns = dispatch_timed(path.to_path_buf(), data, cfg);
        for v in &mut vulns {
            v.file_path = display_name.to_string();
        }
        result.vulnerabilities.extend(vulns);
    }
    result.scanned_files = 1;

    result.vulnerabilities.sort_by(|a, b| b.severity.score().cmp(&a.severity.score()));
    apply_fp_hints(&mut result.vulnerabilities);
    result.finalize();
    result
}

// ─── Heuristiques de faux positifs (repris du desktop) ───────────────────────

fn apply_fp_hints(vulns: &mut [Vulnerability]) {
    for v in vulns.iter_mut() {
        v.fp_hint = detect_fp(&v.file_path, v.matched_pattern.as_deref(), &v.category);
    }
}

fn detect_fp(
    path: &str,
    matched: Option<&str>,
    category: &crate::models::VulnCategory,
) -> Option<String> {
    use crate::models::VulnCategory::*;

    let path_l = path.to_lowercase();
    let matched_l = matched.unwrap_or("").to_lowercase();

    let path_segs: Vec<&str> = path.split(['/', '\\']).collect();
    let test_dirs = ["test", "tests", "spec", "specs", "mock", "mocks",
                     "fixture", "fixtures", "example", "examples",
                     "sample", "samples", "demo", "__tests__"];
    for seg in &path_segs {
        let s = seg.to_lowercase();
        if test_dirs.iter().any(|t| s == *t || s.starts_with(&format!("{}_", t)) || s.ends_with(&format!("_{}", t))) {
            return Some(format!(
                "Possible faux positif — fichier dans un contexte test/exemple (dossier «{}»). \
                 Vérifier si ce code est exécuté en production.",
                seg
            ));
        }
    }
    if path_l.ends_with("_test.rs") || path_l.ends_with("_test.go") ||
       path_l.ends_with(".test.js") || path_l.ends_with(".spec.ts") ||
       path_l.ends_with(".spec.js") {
        return Some(
            "Possible faux positif — fichier de test (nom contient _test/.test/.spec). \
             Vérifier si ce code est exécuté en production.".to_string()
        );
    }

    let placeholders = ["placeholder", "your_api", "your-api", "your_key", "your-key",
                        "changeme", "replace_me", "insert_key", "insert_secret",
                        "example.com", "example_", "_example", "fake_", "dummy_",
                        "sample_key", "demo_key", "test_key", "test_secret",
                        "xxxx", "1234567890abcdef", "abcdefghijklmnop"];
    for p in &placeholders {
        if matched_l.contains(p) {
            return Some(format!(
                "Possible faux positif — valeur détectée ressemble à un placeholder/exemple (\"{}\"). \
                 Peu probable que ce soit une vraie fuite.",
                &matched_l[..matched_l.len().min(40)]
            ));
        }
    }

    if matches!(category, WeakCrypto) {
        if matched_l.contains("md5") || matched_l.contains("sha1") || matched_l.contains("sha-1") {
            return Some(
                "Possible faux positif — MD5/SHA-1 fréquemment utilisés pour \
                 checksums de fichiers ou déduplication (usage non-sécuritaire légitime). \
                 Vérifier que ce n'est pas utilisé pour hacher des mots de passe.".to_string()
            );
        }
        if matched_l.contains("random") {
            return Some(
                "Possible faux positif — random() peut être utilisé à des fins \
                 non-sécuritaires (simulation, jeux, tri aléatoire).".to_string()
            );
        }
    }

    if matches!(category, CommandInjection) {
        let ext = path_l.rsplit('.').next().unwrap_or("");
        if matches!(ext, "rs" | "go" | "c" | "cpp" | "cs") {
            return Some(
                "Possible faux positif — les outils système en Rust/Go/C# utilisent \
                 légitimement l'exécution de processus. Vérifier si les paramètres \
                 passés à la commande peuvent être contrôlés par un attaquant.".to_string()
            );
        }
    }

    if matches!(category, CorsMisconfiguration) {
        if path_l.contains("nginx") || path_l.contains("static") ||
           path_l.contains("cdn")   || path_l.contains("assets") {
            return Some(
                "Possible faux positif — CORS wildcard (*) acceptable pour les ressources \
                 statiques publiques. Problématique uniquement pour les endpoints API authentifiés.".to_string()
            );
        }
    }

    if matches!(category, HighEntropyString) {
        if path_l.ends_with(".lock") || path_l.ends_with(".sum") ||
           path_l.contains("package-lock") || path_l.contains("yarn.lock") ||
           path_l.contains("cargo.lock") {
            return Some(
                "Possible faux positif — fichier de lock contenant des hashes \
                 d'intégrité de dépendances (non-secrets).".to_string()
            );
        }
        let hex_only: bool = matched_l.chars().all(|c| c.is_ascii_hexdigit() || c == '"' || c == '\'');
        if hex_only && matched_l.len() >= 40 {
            return Some(
                "Possible faux positif — chaîne hexadécimale longue pouvant être \
                 un hash de commit, fingerprint d'asset ou checksum (non-secret).".to_string()
            );
        }
    }

    None
}
