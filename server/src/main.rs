//! main.rs — SecuScan Web : API axum + frontend statique.
//! POST /api/scan : multipart (file = source/binaire/ZIP projet) → ScanResult JSON.
//! Le scan se fait dans un répertoire temporaire isolé, supprimé après usage.

mod engine;
mod export;
mod models;
mod parsers;

use std::{
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use axum::{
    extract::{DefaultBodyLimit, Multipart, State},
    http::{header, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use tokio::sync::Semaphore;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::KeyExtractor, GovernorError, GovernorLayer,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
};

use engine::scanner_web;
use models::ScanConfig;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_UPLOAD_BYTES: usize = 80 * 1024 * 1024; // 80 MB upload (ZIP compressé)
const MAX_INFLIGHT: usize = 2;
// Anti zip-bomb : limites à l'extraction
const MAX_UNCOMPRESSED: u64 = 600 * 1024 * 1024; // 600 MB décompressés
const MAX_ZIP_ENTRIES: usize = 20_000;

// ─── Extraction IP cliente ────────────────────────────────────────────────────

#[derive(Clone)]
struct ClientIpExtractor;

impl KeyExtractor for ClientIpExtractor {
    type Key = IpAddr;
    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        let header_ip = |name: &str| -> Option<IpAddr> {
            req.headers().get(name)?.to_str().ok()?.split(',').next()?.trim().parse().ok()
        };
        header_ip("cf-connecting-ip")
            .or_else(|| header_ip("x-real-ip"))
            .or_else(|| {
                req.extensions()
                    .get::<axum::extract::ConnectInfo<SocketAddr>>()
                    .map(|ci| ci.0.ip())
            })
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

// ─── Erreur API ───────────────────────────────────────────────────────────────

struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}
fn bad_request(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
fn internal(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
}

// ─── Répertoire temporaire auto-nettoyé (RAII) ───────────────────────────────

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> std::io::Result<Self> {
        let p = std::env::temp_dir().join(format!("secuscan_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p)?;
        Ok(TempDir(p))
    }
    fn path(&self) -> &Path { &self.0 }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ─── Détection ZIP ────────────────────────────────────────────────────────────

fn looks_like_zip(bytes: &[u8], name: &str) -> bool {
    bytes.starts_with(b"PK\x03\x04") || name.to_lowercase().ends_with(".zip")
}

/// Extrait un ZIP dans `dest` avec protections anti zip-slip + anti zip-bomb.
fn extract_zip_safe(data: &[u8], dest: &Path) -> Result<usize, ApiError> {
    let reader = std::io::Cursor::new(data);
    let mut zip = zip::ZipArchive::new(reader)
        .map_err(|e| bad_request(format!("Archive ZIP invalide : {e}")))?;

    if zip.len() > MAX_ZIP_ENTRIES {
        return Err(bad_request(format!("Trop d'entrées dans l'archive (> {MAX_ZIP_ENTRIES})")));
    }

    let mut total_uncompressed: u64 = 0;
    let mut extracted = 0usize;

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| bad_request(format!("Entrée ZIP {i} : {e}")))?;

        // Anti zip-slip : refuse les chemins absolus ou contenant ".."
        let Some(enclosed) = entry.enclosed_name() else {
            continue; // chemin dangereux → ignoré
        };
        if enclosed.components().any(|c| matches!(c, Component::ParentDir | Component::RootDir)) {
            continue;
        }

        if entry.is_dir() {
            continue;
        }

        total_uncompressed = total_uncompressed
            .checked_add(entry.size())
            .ok_or_else(|| bad_request("Overflow taille ZIP"))?;
        if total_uncompressed > MAX_UNCOMPRESSED {
            return Err(bad_request("Archive trop volumineuse une fois décompressée (zip-bomb ?)"));
        }

        let out_path = dest.join(&enclosed);
        // Garde-fou : la cible doit rester sous `dest`
        if !out_path.starts_with(dest) {
            continue;
        }
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                tracing::error!("mkdir extraction ZIP : {e}");
                internal("Erreur serveur interne")
            })?;
        }

        let mut buf = Vec::new();
        // Limite par fichier alignée sur le cap global
        entry
            .by_ref()
            .take(MAX_UNCOMPRESSED)
            .read_to_end(&mut buf)
            .map_err(|e| {
                tracing::error!("Lecture entrée ZIP : {e}");
                internal("Erreur serveur interne")
            })?;
        std::fs::write(&out_path, &buf).map_err(|e| {
            tracing::error!("Écriture extraction ZIP : {e}");
            internal("Erreur serveur interne")
        })?;
        extracted += 1;
    }

    Ok(extracted)
}

/// Nettoie un nom de fichier (pas de chemin, pas de caractères piégeux).
fn safe_basename(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or("upload")
        .chars()
        .filter(|c| !matches!(c, '\0' | '/' | '\\'))
        .take(255)
        .collect::<String>()
        .trim_matches('.')
        .to_string()
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    // Ne pas exposer la version en production (fingerprinting)
    Json(serde_json::json!({ "status": "ok" }))
}

async fn scan(
    State(state): State<Arc<Semaphore>>,
    mut multipart: Multipart,
) -> Result<Response, ApiError> {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_name = String::from("upload");

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| bad_request(format!("Multipart invalide : {e}")))?
    {
        if field.name() == Some("file") {
            file_name = field.file_name().unwrap_or("upload").to_string();
            let data = field.bytes().await.map_err(|e| bad_request(format!("Lecture fichier : {e}")))?;
            file_bytes = Some(data.to_vec());
        }
    }

    let bytes = file_bytes.ok_or_else(|| bad_request("Champ 'file' manquant"))?;
    if bytes.is_empty() {
        return Err(bad_request("Fichier vide"));
    }

    let base = safe_basename(&file_name);
    let is_zip = looks_like_zip(&bytes, &file_name);

    let _permit = state
        .acquire()
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "Arrêt en cours".into()))?;

    let result = tokio::task::spawn_blocking(move || -> Result<models::ScanResult, ApiError> {
        let tmp = TempDir::new().map_err(|e| {
            tracing::error!("Création répertoire temporaire : {e}");
            internal("Erreur serveur interne")
        })?;
        let cfg = ScanConfig::default();

        if is_zip {
            let n = extract_zip_safe(&bytes, tmp.path())?;
            if n == 0 {
                return Err(bad_request("Archive vide ou aucun fichier exploitable"));
            }
            let display = base.strip_suffix(".zip").unwrap_or(&base);
            Ok(scanner_web::scan_tree(tmp.path(), display, cfg))
        } else {
            let file_path = tmp.path().join(&base);
            std::fs::write(&file_path, &bytes).map_err(|e| {
                tracing::error!("Écriture fichier temporaire : {e}");
                internal("Erreur serveur interne")
            })?;
            Ok(scanner_web::scan_single(&file_path, &base, cfg))
        }
        // tmp supprimé ici (Drop)
    })
    .await
    .map_err(|e| internal(format!("Tâche interrompue : {e}")))??;

    Ok(Json(result).into_response())
}

// ─── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3005);
    let static_dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| "../web/dist".into());
    // Vérifie que le répertoire statique existe pour détecter tôt une mauvaise config
    if !std::path::Path::new(&static_dir).exists() {
        tracing::warn!("STATIC_DIR '{static_dir}' n'existe pas — le frontend ne sera pas servi");
    }
    let allowed_origin = std::env::var("ALLOWED_ORIGIN")
        .unwrap_or_else(|_| "https://secuscan-app.heiphaistos.org".into());

    let permits = Arc::new(Semaphore::new(MAX_INFLIGHT));

    // Rate-limit : burst 8, recharge 1 / 8 s (scan = opération lourde)
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(8)
            .burst_size(8)
            .key_extractor(ClientIpExtractor)
            .finish()
            .ok_or_else(|| anyhow!("Config rate-limit invalide"))?,
    );

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(
            allowed_origin.parse::<HeaderValue>()
                .map_err(|e| anyhow!("ALLOWED_ORIGIN invalide ('{allowed_origin}'): {e}"))?,
        ));

    // Security headers appliqués à toutes les réponses (API + static)
    let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'";
    let sec_headers = tower::ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(csp),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ));

    let api = Router::new()
        .route("/api/scan", post(scan))
        .route("/api/health", get(health))
        .layer(cors)
        .layer(GovernorLayer { config: governor_conf })
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(180)))
        .with_state(permits);

    let index = format!("{static_dir}/index.html");
    let static_service = ServeDir::new(&static_dir).fallback(ServeFile::new(&index));
    let app = api.fallback_service(static_service).layer(sec_headers);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("SecuScan Web v{VERSION} — écoute sur http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Arrêt demandé");
        })
        .await?;

    Ok(())
}
