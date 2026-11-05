use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use vercel_runtime::{axum::VercelLayer, Error};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Device {
    pub hostname: String,
    pub alias: Option<String>,
    pub ip: String,
    pub public_ip: Option<String>,
    pub status: String,        // "NORMAL" ou "QUARENTENA"
    pub last_seen: u64,
    pub last_alert: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Incident {
    pub id: String,
    pub timestamp: u64,
    pub hostname: String,
    pub alias: Option<String>,
    pub ip: String,
    pub public_ip: Option<String>,
    pub event_type: String,
    pub details: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BoletoAlert {
    pub id: String,
    pub timestamp: u64,
    pub hostname: String,
    pub alias: Option<String>,
    pub ip: String,
    pub arquivo: String,
    pub confiavel: bool,
    pub score_risco: u32,
    pub recomendacao: String,
    pub detalhes_alerta: Vec<String>,
    #[serde(default)]
    pub status_auditoria: Option<String>, // "PENDENTE", "BLOQUEADO", "APROVADO"
}

#[derive(Deserialize)]
pub struct HeartbeatPayload {
    pub hostname: String,
    pub ip: String,
}

#[derive(Deserialize)]
pub struct AlertPayload {
    pub hostname: String,
    pub details: String,
}

#[derive(Deserialize)]
pub struct RenamePayload {
    pub alias: String,
}

#[derive(Deserialize, Debug)]
pub struct FinancialReportPayload {
    pub hostname: String,
    #[serde(default)]
    pub ip: String,
    pub arquivo: String,
    #[serde(default)]
    pub confiavel: bool, // <-- Essencial para o if !payload.confiavel funcionar
    pub score_risco: u32,
    pub recomendacao: String,
    #[serde(default)]
    pub fatores_risco: Vec<String>,
}

#[derive(Deserialize)]
pub struct BoletoActionPayload {
    pub action: String, // "bloquear" ou "auditar"
}

#[derive(Serialize)]
pub struct CommandResponse {
    pub should_isolate: bool,
}

#[derive(Default)]
pub struct AppData {
    pub devices: HashMap<String, Device>,
    pub incidents: Vec<Incident>,
    pub boleto_alerts: Vec<BoletoAlert>,
}

type AppState = Arc<Mutex<AppData>>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let state: AppState = Arc::new(Mutex::new(AppData::default()));

    let router = Router::new()
        .route("/", get(dashboard_handler))
        .route("/api/devices", get(get_devices))
        .route("/api/incidents", get(get_incidents))
        .route("/api/boletos", get(get_boleto_alerts))
        .route("/api/boletos/{id}/action", post(handle_boleto_action))
        .route("/api/heartbeat", post(handle_heartbeat))
        .route("/api/alert", post(handle_alert))
        .route("/api/audit/financial", post(handle_financial_audit))
        .route("/api/device/{hostname}/toggle", post(toggle_quarantine))
        .route("/api/device/{hostname}/rename", post(rename_device))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let app = ServiceBuilder::new()
        .layer(VercelLayer::new())
        .service(router);

    vercel_runtime::run(app).await
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Retorna lista de máquinas em JSON para o frontend
async fn get_devices(State(state): State<AppState>) -> Json<Vec<Device>> {
    let app_data = state.lock().unwrap();
    Json(app_data.devices.values().cloned().collect())
}

// Retorna histórico de ocorrências e quarentenas para o frontend
async fn get_incidents(State(state): State<AppState>) -> Json<Vec<Incident>> {
    let app_data = state.lock().unwrap();
    Json(app_data.incidents.clone())
}

// Retorna lista exclusiva de auditorias e avisos sobre boletos
async fn get_boleto_alerts(State(state): State<AppState>) -> Json<Vec<BoletoAlert>> {
    let app_data = state.lock().unwrap();
    Json(app_data.boleto_alerts.clone())
}

// Trata ações de bloquear ou auditar (aceitar) um boleto pelo operador
async fn handle_boleto_action(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<BoletoActionPayload>,
) -> Json<serde_json::Value> {
    let mut app_data = state.lock().unwrap();
    if let Some(alert) = app_data.boleto_alerts.iter_mut().find(|b| b.id == id) {
        if payload.action == "bloquear" {
            alert.status_auditoria = Some("BLOQUEADO".to_string());
        } else if payload.action == "auditar" || payload.action == "aprovar" {
            alert.status_auditoria = Some("APROVADO".to_string());
        }
    }
    Json(serde_json::json!({ "ok": true }))
}

// Recebe heartbeat do Agent e diz se ele deve estar isolado ou não
async fn handle_heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<HeartbeatPayload>,
) -> Json<CommandResponse> {
    let mut app_data = state.lock().unwrap();

    // Captura o IP real da conexão (seja local ou via proxy/Vercel)
    let wan_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        });

    let lan_ip = if !payload.ip.is_empty() && payload.ip != "Endpoint Conectado" && payload.ip != "Local" {
        payload.ip.clone()
    } else {
        wan_ip.clone().unwrap_or_else(|| "127.0.0.1".to_string())
    };

    let entry = app_data.devices.entry(payload.hostname.clone()).or_insert_with(|| Device {
        hostname: payload.hostname.clone(),
        alias: None,
        ip: lan_ip.clone(),
        public_ip: wan_ip.clone(),
        status: "NORMAL".to_string(),
        last_seen: now_secs(),
        last_alert: None,
    });

    entry.last_seen = now_secs();
    entry.ip = lan_ip;
    entry.public_ip = wan_ip;

    Json(CommandResponse {
        should_isolate: entry.status == "QUARENTENA",
    })
}

// Recebe alerta crítico do Agent
async fn handle_alert(
    State(state): State<AppState>,
    Json(payload): Json<AlertPayload>,
) -> Json<serde_json::Value> {
    let mut app_data = state.lock().unwrap();
    let mut ip_salvo = "Local".to_string();
    let mut public_ip_salvo = None;
    let mut alias_salvo = None;

    if let Some(device) = app_data.devices.get_mut(&payload.hostname) {
        device.status = "QUARENTENA".to_string();
        device.last_alert = Some(payload.details.clone());
        ip_salvo = device.ip.clone();
        public_ip_salvo = device.public_ip.clone();
        alias_salvo = device.alias.clone();
        println!("🚨 [ADM ALERTA] Dispositivo {} entrou em quarentena automática!", payload.hostname);
    }

    let incident = Incident {
        id: format!("INC-{}", now_secs() % 100000),
        timestamp: now_secs(),
        hostname: payload.hostname,
        alias: alias_salvo,
        ip: ip_salvo,
        public_ip: public_ip_salvo,
        event_type: "AUTO_ISOLAMENTO".to_string(),
        details: payload.details,
    };
    app_data.incidents.insert(0, incident);

    Json(serde_json::json!({ "status": "acknowledged" }))
}

// Recebe relatório do validador de boletos enviado pelo Agent
async fn handle_financial_audit(
    State(state): State<AppState>,
    Json(payload): Json<FinancialReportPayload>,
) -> Json<serde_json::Value> {
    let mut app_data = state.lock().unwrap();
    let mut ip_salvo = "Local".to_string();
    let mut alias_salvo = None;

    if let Some(device) = app_data.devices.get_mut(&payload.hostname) {
        ip_salvo = device.ip.clone();
        alias_salvo = device.alias.clone();

        if !payload.confiavel {
            device.last_alert = Some(format!("Boleto Suspeito: {}", payload.arquivo));
        }
    }

    let status_inicial = if payload.confiavel {
        Some("APROVADO".to_string())
    } else {
        Some("PENDENTE".to_string())
    };

    let boleto_entry = BoletoAlert {
        id: format!("BOL-{}", now_secs() % 100000),
        timestamp: now_secs(),
        hostname: payload.hostname.clone(),
        alias: alias_salvo.clone(),
        ip: ip_salvo.clone(),
        arquivo: payload.arquivo.clone(),
        confiavel: payload.confiavel,
        score_risco: payload.score_risco,
        recomendacao: payload.recomendacao.clone(),
        detalhes_alerta: payload.fatores_risco.clone(),
        status_auditoria: status_inicial,
    };
    app_data.boleto_alerts.insert(0, boleto_entry);

    // Se houver fraude comprovada, também registra no histórico geral de incidentes
    if !payload.confiavel {
        let incident = Incident {
            id: format!("FRAUD-{}", now_secs() % 100000),
            timestamp: now_secs(),
            hostname: payload.hostname,
            alias: alias_salvo,
            ip: ip_salvo,
            public_ip: None,
            event_type: "FRAUDE_BOLETO".to_string(),
            details: format!(
                "Documento: '{}' | Risco: {}/100 | {}",
                payload.arquivo,
                payload.score_risco,
                payload.fatores_risco.join("; ")
            ),
        };
        app_data.incidents.insert(0, incident);
    }

    Json(serde_json::json!({ "status": "acknowledged" }))
}

// Botão de alternar Quarentena pelo Administrador
async fn toggle_quarantine(
    Path(hostname): Path<String>,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let mut app_data = state.lock().unwrap();
    if let Some(device) = app_data.devices.get_mut(&hostname) {
        let (action_type, desc) = if device.status == "QUARENTENA" {
            device.status = "NORMAL".to_string();
            device.last_alert = None;
            println!("🔓 [ADM] Dispositivo {} liberado pelo operador.", hostname);
            ("LIBERACAO", "Dispositivo liberado manualmente pelo operador no painel")
        } else {
            device.status = "QUARENTENA".to_string();
            device.last_alert = Some("Quarentena acionada manualmente pelo ADM".to_string());
            println!("🔒 [ADM] Dispositivo {} colocado em quarentena pelo operador.", hostname);
            ("QUARENTENA_MANUAL", "Contenção de rede iniciada manualmente pelo operador")
        };

        let incident = Incident {
            id: format!("ACT-{}", now_secs() % 100000),
            timestamp: now_secs(),
            hostname: device.hostname.clone(),
            alias: device.alias.clone(),
            ip: device.ip.clone(),
            public_ip: device.public_ip.clone(),
            event_type: action_type.to_string(),
            details: desc.to_string(),
        };
        app_data.incidents.insert(0, incident);
    }
    Json(serde_json::json!({ "ok": true }))
}

// Renomeia o dispositivo para identificação amigável no painel
async fn rename_device(
    Path(hostname): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<RenamePayload>,
) -> Json<serde_json::Value> {
    let mut app_data = state.lock().unwrap();
    if let Some(device) = app_data.devices.get_mut(&hostname) {
        let trimmed = payload.alias.trim();
        device.alias = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }
    Json(serde_json::json!({ "ok": true }))
}

// Interface Web Completa com Tailwind CSS
async fn dashboard_handler() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>cypher — Security Gateway Console</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['"Plus Jakarta Sans"', 'sans-serif'],
                        mono: ['"JetBrains Mono"', 'monospace'],
                    },
                    colors: {
                        cypher: {
                            base: '#1D59F2',
                            hover: '#1546cb',
                            dark: '#0f3192',
                            light: '#e9f0fe',
                        },
                        surface: {
                            950: '#070b14',
                            900: '#0c1322',
                            850: '#111b30',
                            800: '#182542',
                            700: '#25355a',
                        }
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-surface-950 text-slate-100 min-h-screen font-sans antialiased flex flex-col justify-between selection:bg-cypher-base selection:text-white">

    <!-- Definição SVG da Logo Idêntica (32 Círculos Orbitais em viewBox 0 0 100 100) -->
<!-- Logo oficial CYPHER -->
<svg xmlns="http://www.w3.org/2000/svg"
     style="position: absolute; width: 0; height: 0; overflow: hidden;">

    <symbol id="cypher-exact-mark" viewBox="0 0 215 203">
        <g fill='#fff'>
            <circle cx="109.04" cy="37.80" r="10.69"/>
            <circle cx="134.69" cy="30.12" r="2.26"/>
            <circle cx="149.44" cy="34.40" r="2.82"/>
            <circle cx="84.46" cy="42.17" r="7.92"/>
            <circle cx="133.61" cy="45.60" r="7.74"/>
            <circle cx="163.79" cy="44.72" r="5.67"/>
            <circle cx="61.37" cy="52.54" r="8.21"/>
            <circle cx="150.65" cy="60.04" r="5.56"/>
            <circle cx="103.71" cy="57.50" r="2.11"/>
            <circle cx="177.30" cy="63.90" r="8.48"/>
            <circle cx="90.63" cy="60.63" r="3.09"/>
            <circle cx="44.00" cy="67.43" r="4.41"/>
            <circle cx="75.94" cy="68.85" r="4.58"/>
            <circle cx="159.40" cy="74.96" r="2.82"/>
            <circle cx="59.25" cy="84.62" r="7.78"/>
            <circle cx="181.56" cy="90.00" r="11.30"/>
            <circle cx="36.77" cy="84.43" r="3.34"/>
            <circle cx="162.80" cy="87.50" r="1.78"/>
            <circle cx="45.82" cy="110.67" r="12.68"/>
            <circle cx="174.22" cy="116.86" r="8.00"/>
            <circle cx="69.00" cy="112.50" r="2.88"/>
            <circle cx="189.50" cy="121.20" r="1.78"/>
            <circle cx="71.70" cy="128.09" r="4.85"/>
            <circle cx="47.32" cy="137.84" r="8.76"/>
            <circle cx="159.30" cy="134.35" r="5.08"/>
            <circle cx="183.72" cy="134.83" r="3.83"/>
            <circle cx="81.65" cy="143.48" r="5.29"/>
            <circle cx="143.50" cy="143.50" r="3.19"/>
            <circle cx="128.88" cy="146.59" r="2.33"/>
            <circle cx="172.10" cy="149.28" r="5.78"/>
            <circle cx="62.30" cy="156.72" r="6.89"/>
            <circle cx="97.94" cy="158.25" r="8.18"/>
            <circle cx="125.15" cy="167.31" r="13.04"/>
            <circle cx="152.26" cy="162.21" r="8.46"/>
            <circle cx="77.16" cy="169.19" r="3.70"/>
            <circle cx="91.80" cy="175.20" r="2.19"/>
        </g>
    </symbol>
</svg>
    <!-- ======================================================== -->
    <!-- VIEW 1: TELA DE LOGIN                                    -->
    <!-- ======================================================== -->
    <div id="login-view" class="flex-1 flex flex-col items-center justify-center px-4 py-12 relative overflow-hidden bg-surface-950">
        <!-- Brilho azul ambiental da marca -->
        <div class="absolute -top-32 -left-32 w-96 h-96 bg-cypher-base/20 rounded-full blur-[100px] pointer-events-none"></div>
        <div class="absolute -bottom-32 -right-32 w-96 h-96 bg-cypher-base/15 rounded-full blur-[100px] pointer-events-none"></div>

        <div class="w-full max-w-md relative z-10">
            <!-- Emblema idêntico à imagem: Fundo Azul Royal + Logo Marfim -->
            <div class="flex w-full justify-center mb-10 select-none">
                <div class="relative">
                    <div class="absolute right-full mr-4 top-1/2 -translate-y-1/2 w-20 h-20 flex-shrink-0">
                        <svg viewBox="0 0 215 203" class="w-full h-full fill-white">
                            <use href='#cypher-exact-mark'/>
                        </svg>
                    </div>

                    <span class="text-5xl font-extrabold tracking-tight text-white lowercase font-sans">
                        cypher
                    </span>
                </div>
            </div>

            <!-- Formulário de Login -->
            <div class="bg-surface-900/90 border border-surface-800 rounded-3xl p-8 shadow-2xl backdrop-blur-xl">
                <div class="mb-6">
                    <h2 class="text-lg font-bold text-white tracking-tight">Painel Administrativo</h2>
                    <p class="text-xs text-slate-400 mt-0.5">Informe as credenciais do operador autorizado</p>
                </div>

                <form id="login-form" class="space-y-4 pb-2" onsubmit="handleLogin(event)">
                    <div>
                        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Usuário</label>
                        <input id="login-user" type="text" required placeholder="admin" autocomplete="off"
                            class="w-full bg-surface-950 border border-surface-700 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cypher-base focus:ring-2 focus:ring-cypher-base/20 transition-all font-mono">
                    </div>

                    <div>
                        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Senha</label>
                        <input id="login-pass" type="password" required placeholder="Digite sua senha"
                            class="w-full bg-surface-950 border border-surface-700 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cypher-base focus:ring-2 focus:ring-cypher-base/20 transition-all font-mono mb-4">
                    </div>

                    <div id="login-error" class="hidden text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 p-3 rounded-xl font-medium">
                        Credenciais inválidas.
                    </div>

                    <button type="submit"
                        class="w-full bg-cypher-base hover:bg-cypher-hover text-white font-bold text-sm py-3.5 px-4 rounded-xl transition-all shadow-lg shadow-cypher-base/30 hover:shadow-cypher-base/50 mt-2 flex items-center justify-center gap-2">
                        <span>Entrar no Sistema</span>
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                    </button>
                </form>
            </div>
        </div>
    </div>

    <!-- ======================================================== -->
    <!-- VIEW 2: PAINEL PRINCIPAL PAGINADO                        -->
    <!-- ======================================================== -->
    <div id="app-view" class="hidden flex-1 flex flex-col">
        <!-- Topo / Navbar Profissional -->
        <header class="border-b border-surface-800 bg-surface-900/90 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
            <div class="flex items-center space-x-8">
                <!-- Marca Oficial com Logo Idêntica -->
                <div class="flex items-center gap-3 select-none">
                    <div class="w-8 h-8 flex-shrink-0 flex items-center justify-center">
                        <svg viewBox="0 0 215 203" class="w-full h-full fill-white">
                            <use href='#cypher-exact-mark'/>
                        </svg>
                    </div>
                    <span class="text-2xl font-extrabold tracking-tight text-white lowercase font-sans">cypher</span>
                    <span class="text-[10px] font-bold uppercase tracking-wider bg-cypher-base/15 text-blue-400 border border-cypher-base/30 px-2 py-0.5 rounded-full font-mono">ADM</span>
                </div>

                <!-- Abas Paginadas -->
                <nav class="flex items-center space-x-1.5 text-xs font-semibold">
                    <button onclick="switchTab('devices')" id="tab-btn-devices"
                        class="tab-btn px-4 py-2 rounded-xl transition-all flex items-center gap-2 bg-cypher-base text-white shadow-sm shadow-cypher-base/30">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                        <span>Endpoints</span>
                        <span id="nav-count" class="bg-black/30 text-white px-2 py-0.2 rounded-full text-[10px] font-mono">0</span>
                    </button>

                    <button onclick="switchTab('boletos')" id="tab-btn-boletos"
                        class="tab-btn px-4 py-2 rounded-xl transition-all flex items-center gap-2 text-slate-400 hover:text-white hover:bg-surface-800">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                        <span>Avisos de Boletos</span>
                        <span id="boletos-count" class="bg-rose-500/20 text-rose-400 border border-rose-500/30 px-2 py-0.2 rounded-full text-[10px] font-mono">0</span>
                    </button>

                    <button onclick="switchTab('incidents')" id="tab-btn-incidents"
                        class="tab-btn px-4 py-2 rounded-xl transition-all flex items-center gap-2 text-slate-400 hover:text-white hover:bg-surface-800">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                        <span>Histórico & Ocorrências</span>
                    </button>

                    <button onclick="switchTab('account')" id="tab-btn-account"
                        class="tab-btn px-4 py-2 rounded-xl transition-all flex items-center gap-2 text-slate-400 hover:text-white hover:bg-surface-800">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
                        <span>Usuário (Conta)</span>
                    </button>
                </nav>
            </div>

            <!-- Direita / Sessão -->
            <div class="flex items-center space-x-4">
                <div class="flex items-center gap-2 bg-surface-950 border border-surface-800 px-3 py-1.5 rounded-xl text-xs font-mono text-slate-400 hidden sm:flex">
                    <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span id="clock">00:00:00</span>
                </div>
                <button onclick="logout()" 
                    class="text-xs bg-surface-850 hover:bg-rose-500/20 text-slate-300 hover:text-rose-400 border border-surface-700/80 hover:border-rose-500/30 px-3.5 py-1.5 rounded-xl transition-all font-semibold">
                    Sair
                </button>
            </div>
        </header>

        <!-- Conteúdo Principal -->
        <main class="max-w-7xl mx-auto w-full px-6 py-8 flex-1">
            
            <!-- ============================================== -->
            <!-- ABA 1: ENDPOINTS & IPS                         -->
            <!-- ============================================== -->
            <section id="tab-devices" class="tab-pane space-y-6">
                <!-- Métricas do SOC -->
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div class="bg-surface-900 border border-surface-800 p-5 rounded-2xl shadow-sm">
                        <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total de Endpoints</span>
                        <div id="stat-total" class="text-3xl font-extrabold text-white mt-1">0</div>
                    </div>
                    <div class="bg-surface-900 border border-surface-800 p-5 rounded-2xl shadow-sm">
                        <span class="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Dispositivos Seguros</span>
                        <div id="stat-normal" class="text-3xl font-extrabold text-emerald-400 mt-1">0</div>
                    </div>
                    <div class="bg-surface-900 border border-surface-800 p-5 rounded-2xl shadow-sm">
                        <span class="text-xs font-semibold text-rose-400 uppercase tracking-wider">Em Quarentena</span>
                        <div id="stat-quarantine" class="text-3xl font-extrabold text-rose-400 mt-1">0</div>
                    </div>
                    <div class="bg-surface-900 border border-surface-800 p-5 rounded-2xl shadow-sm">
                        <span class="text-xs font-semibold text-cypher-base uppercase tracking-wider">Defesa Ativa</span>
                        <div class="text-sm font-bold text-slate-200 mt-2.5 flex items-center gap-2">
                            <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
                            <span>Canary + Auto-Isolamento</span>
                        </div>
                    </div>
                </div>

                <!-- Título -->
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-surface-800 pb-4">
                    <div>
                        <h2 class="text-lg font-bold text-white tracking-tight">Estações Monitoradas</h2>
                        <p class="text-xs text-slate-400 mt-0.5">Visualização de IPs, apelidos amigáveis e controle individual de quarentena</p>
                    </div>
                    <span class="text-xs font-mono text-slate-500 flex items-center gap-1.5 self-start sm:self-auto">
                        <span class="w-1.5 h-1.5 rounded-full bg-cypher-base"></span>
                        Atualização ativa a cada 2.5s
                    </span>
                </div>

                <!-- Grid de Computadores -->
                <div id="device-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    <div class="col-span-full py-20 text-center text-slate-500 border border-dashed border-surface-800 rounded-3xl bg-surface-900/40">
                        <svg class="w-10 h-10 mx-auto text-slate-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                        <p class="text-sm font-medium">Nenhum computador conectado no momento.</p>
                        <p class="text-xs text-slate-600 mt-1">Inicie o CYPHER Agent em um terminal Windows para registrá-lo automaticamente.</p>
                    </div>
                </div>
            </section>

            <!-- ============================================== -->
            <!-- ABA: AVISOS & AUDITORIA DE BOLETOS             -->
            <!-- ============================================== -->
            <section id="tab-boletos" class="tab-pane hidden space-y-6">
                <!-- Métricas Exclusivas de Boletos -->
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div class="bg-surface-900 border border-surface-800 p-5 rounded-2xl shadow-sm">
                        <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Avisos Registrados</span>
                        <div id="stat-boletos-total" class="text-3xl font-extrabold text-white mt-1">0</div>
                    </div>
                    <div class="bg-surface-900 border border-surface-800 p-5 rounded-2xl shadow-sm">
                        <span class="text-xs font-semibold text-rose-400 uppercase tracking-wider">Boletos Bloqueados</span>
                        <div id="stat-boletos-fraudes" class="text-3xl font-extrabold text-rose-400 mt-1">0</div>
                    </div>
                    <div class="bg-surface-900 border border-surface-800 p-5 rounded-2xl shadow-sm">
                        <span class="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Auditados / Aprovados</span>
                        <div id="stat-boletos-aprovados" class="text-3xl font-extrabold text-emerald-400 mt-1">0</div>
                    </div>
                </div>

                <div class="flex items-center justify-between border-b border-surface-800 pb-4">
                    <div>
                        <h2 class="text-lg font-bold text-white tracking-tight">Avisos e Auditoria de Boletos</h2>
                        <p class="text-xs text-slate-400 mt-0.5">Alertas de adulteração de linha digitável (bolware), checksums inválidos e divergências</p>
                    </div>
                    <button onclick="fetchBoletoAlerts()" class="text-xs text-cypher-base hover:underline font-semibold flex items-center gap-1">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                        <span>Atualizar Avisos</span>
                    </button>
                </div>

                <div class="bg-surface-900 border border-surface-800 rounded-2xl overflow-hidden shadow-xl">
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs">
                            <thead class="bg-surface-950 text-slate-400 border-b border-surface-800 uppercase tracking-wider font-mono text-[11px]">
                                <tr>
                                    <th class="py-3.5 px-4 font-semibold">Registro</th>
                                    <th class="py-3.5 px-4 font-semibold">Horário</th>
                                    <th class="py-3.5 px-4 font-semibold">Computador / Origem</th>
                                    <th class="py-3.5 px-4 font-semibold">Arquivo / Documento</th>
                                    <th class="py-3.5 px-4 font-semibold">Score Risco</th>
                                    <th class="py-3.5 px-4 font-semibold">Status</th>
                                    <th class="py-3.5 px-4 font-semibold">Parecer Técnico</th>
                                    <th class="py-3.5 px-4 font-semibold text-right">Ações</th>
                                </tr>
                            </thead>
                            <tbody id="boletos-tbody" class="divide-y divide-surface-800/60 font-mono">
                                <tr>
                                    <td colspan="8" class="text-center py-12 text-slate-500 font-sans">
                                        Nenhum aviso ou documento financeiro registrado até o momento.
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <!-- ============================================== -->
            <!-- ABA 2: HISTÓRICO & AUDITORIA                   -->
            <!-- ============================================== -->
            <section id="tab-incidents" class="tab-pane hidden space-y-6">
                <div class="flex items-center justify-between border-b border-surface-800 pb-4">
                    <div>
                        <h2 class="text-lg font-bold text-white tracking-tight">Registro de Ocorrências e Quarentenas</h2>
                        <p class="text-xs text-slate-400 mt-0.5">Linha do tempo forense de bloqueios automáticos e liberações</p>
                    </div>
                    <button onclick="fetchIncidents()" class="text-xs text-cypher-base hover:underline font-semibold flex items-center gap-1">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                        <span>Atualizar Tabela</span>
                    </button>
                </div>

                <div class="bg-surface-900 border border-surface-800 rounded-2xl overflow-hidden shadow-xl">
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs">
                            <thead class="bg-surface-950 text-slate-400 border-b border-surface-800 uppercase tracking-wider font-mono text-[11px]">
                                <tr>
                                    <th class="py-3.5 px-4 font-semibold">Protocolo</th>
                                    <th class="py-3.5 px-4 font-semibold">Timestamp</th>
                                    <th class="py-3.5 px-4 font-semibold">Dispositivo</th>
                                    <th class="py-3.5 px-4 font-semibold">Endereço IP</th>
                                    <th class="py-3.5 px-4 font-semibold">Ação / Evento</th>
                                    <th class="py-3.5 px-4 font-semibold">Detalhes</th>
                                </tr>
                            </thead>
                            <tbody id="incidents-tbody" class="divide-y divide-surface-800/60 font-mono">
                                <tr>
                                    <td colspan="6" class="text-center py-12 text-slate-500 font-sans">
                                        Nenhuma ocorrência registrada até o momento.
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <!-- ============================================== -->
            <!-- ABA 3: CONTA DO USUÁRIO                        -->
            <!-- ============================================== -->
            <section id="tab-account" class="tab-pane hidden space-y-6">
                <div class="border-b border-surface-800 pb-4">
                    <h2 class="text-lg font-bold text-white tracking-tight">Informações da Conta</h2>
                    <p class="text-xs text-slate-400 mt-0.5">Perfil autenticado e parâmetros locais do console</p>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div class="bg-surface-900 border border-surface-800 rounded-2xl p-6 flex flex-col items-center text-center">
                        <div class="w-20 h-20 rounded-3xl bg-cypher-base flex items-center justify-center shadow-xl shadow-cypher-base/30 mb-4 p-3.5">
                            <svg viewBox="0 0 215 203" class="w-full h-full fill-white">
                                <use href='#cypher-exact-mark'/>
                            </svg>
                        </div>
                        <h3 class="text-base font-bold text-white">Administrador do Sistema</h3>
                        <span class="text-xs font-mono text-cypher-base font-semibold mt-1">SOC Operator (Root)</span>
                        
                        <div class="w-full border-t border-surface-800 mt-6 pt-4 text-xs text-left space-y-2.5 text-slate-400 font-mono">
                            <div class="flex justify-between">
                                <span>Usuário:</span>
                                <strong class="text-white">admin</strong>
                            </div>
                            <div class="flex justify-between">
                                <span>Status:</span>
                                <strong class="text-emerald-400">Autenticado</strong>
                            </div>
                            <div class="flex justify-between">
                                <span>Escopo:</span>
                                <strong class="text-white">PME / Total Control</strong>
                            </div>
                        </div>
                    </div>

                    <div class="md:col-span-2 bg-surface-900 border border-surface-800 rounded-2xl p-6 space-y-6">
                        <div>
                            <h3 class="text-sm font-bold text-white uppercase tracking-wider mb-3">Diretivas do Gateway</h3>
                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                                <div class="bg-surface-950 p-4 rounded-xl border border-surface-800">
                                    <span class="text-slate-500 block mb-1">Mecanismo de Defesa:</span>
                                    <span class="text-emerald-400 font-bold">WFP / Isolation Rule Injection</span>
                                </div>
                                <div class="bg-surface-950 p-4 rounded-xl border border-surface-800">
                                    <span class="text-slate-500 block mb-1">Detecção em Disco:</span>
                                    <span class="text-cypher-base font-bold">Canary Trap (Honeyfile)</span>
                                </div>
                                <div class="bg-surface-950 p-4 rounded-xl border border-surface-800">
                                    <span class="text-slate-500 block mb-1">Topologia de Rede:</span>
                                    <span class="text-white font-bold">Endpoint-First / Zero-Config</span>
                                </div>
                                <div class="bg-surface-950 p-4 rounded-xl border border-surface-800">
                                    <span class="text-slate-500 block mb-1">Servidor Local:</span>
                                    <span class="text-emerald-400 font-bold">● ONLINE / RESPONDENDO</span>
                                </div>
                            </div>
                        </div>

                        <div class="pt-4 border-t border-surface-800 flex justify-between items-center">
                            <span class="text-xs text-slate-400">Deseja desautenticar este terminal?</span>
                            <button onclick="logout()" class="px-4 py-2 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded-xl text-xs font-semibold transition-all">
                                Encerrar Sessão
                            </button>
                        </div>
                    </div>
                </div>
            </section>
        </main>
    </div>

    <!-- Modal para Renomear Dispositivo -->
    <div id="rename-modal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
        <div class="bg-surface-900 border border-surface-700 rounded-3xl p-6 max-w-md w-full shadow-2xl relative">
            <h3 class="text-base font-bold text-white mb-1">Renomear Endpoint</h3>
            <p class="text-xs text-slate-400 mb-4">Atribua um identificador amigável (ex.: setor ou funcionário) para facilitar a visualização no SOC.</p>

            <form onsubmit="handleRenameSubmit(event)" class="space-y-4">
                <input type="hidden" id="rename-hostname">
                <div>
                    <label class="block text-xs uppercase font-semibold text-slate-400 mb-1.5">Hostname de Origem</label>
                    <input id="rename-display-hostname" type="text" disabled 
                        class="w-full bg-surface-950 border border-surface-800 rounded-xl px-4 py-2.5 text-xs text-slate-500 font-mono cursor-not-allowed">
                </div>

                <div>
                    <label class="block text-xs uppercase font-semibold text-slate-300 mb-1.5">Nome Personalizado / Setor</label>
                    <input id="rename-alias" type="text" placeholder="Ex: Recepção, Financeiro - Máquina 01" required
                        class="w-full bg-surface-950 border border-surface-700 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-cypher-base focus:ring-1 focus:ring-cypher-base font-medium">
                </div>

                <div class="flex items-center justify-end gap-3 pt-2">
                    <button type="button" onclick="closeRenameModal()" 
                        class="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-surface-800 transition-all">
                        Cancelar
                    </button>
                    <button type="submit" 
                        class="px-5 py-2.5 rounded-xl text-xs font-bold bg-cypher-base hover:bg-cypher-hover text-white shadow-md shadow-cypher-base/30 transition-all">
                        Salvar Nome
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Scripts de Controle -->
    <script>
        // Verificação de Sessão (Mock: admin / 123456)
        function checkAuth() {
            const isAuth = sessionStorage.getItem('cypher_auth') === 'true';
            document.getElementById('login-view').classList.toggle('hidden', isAuth);
            document.getElementById('app-view').classList.toggle('hidden', !isAuth);
            if (isAuth) {
                fetchDevices();
                fetchIncidents();
                fetchBoletoAlerts();
            }
        }

        function handleLogin(e) {
            e.preventDefault();
            const u = document.getElementById('login-user').value.trim();
            const p = document.getElementById('login-pass').value.trim();
            const err = document.getElementById('login-error');

            if (u === 'admin' && p === '123456') {
                sessionStorage.setItem('cypher_auth', 'true');
                err.classList.add('hidden');
                checkAuth();
            } else {
                err.classList.remove('hidden');
            }
        }

        function logout() {
            sessionStorage.removeItem('cypher_auth');
            checkAuth();
        }

        // Navegação Paginada em Abas
        function switchTab(tabId) {
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.className = 'tab-btn px-4 py-2 rounded-xl transition-all flex items-center gap-2 text-slate-400 hover:text-white hover:bg-surface-800 font-semibold';
            });

            document.getElementById(`tab-${tabId}`).classList.remove('hidden');
            const activeBtn = document.getElementById(`tab-btn-${tabId}`);
            activeBtn.className = 'tab-btn px-4 py-2 rounded-xl transition-all flex items-center gap-2 bg-cypher-base text-white shadow-sm shadow-cypher-base/30 font-semibold';

            if (tabId === 'incidents') fetchIncidents();
            if (tabId === 'boletos') fetchBoletoAlerts();
        }

        function updateClock() {
            document.getElementById('clock').innerText = new Date().toLocaleTimeString('pt-BR');
        }
        setInterval(updateClock, 1000);
        updateClock();

        // Requisições e Renderização
        async function fetchDevices() {
            if (sessionStorage.getItem('cypher_auth') !== 'true') return;
            try {
                const res = await fetch('/api/devices');
                const devices = await res.json();
                renderDevices(devices);
            } catch (err) {
                console.error("Falha ao buscar dispositivos:", err);
            }
        }

        async function fetchIncidents() {
            if (sessionStorage.getItem('cypher_auth') !== 'true') return;
            try {
                const res = await fetch('/api/incidents');
                const list = await res.json();
                renderIncidents(list);
            } catch (err) {
                console.error("Falha ao buscar incidentes:", err);
            }
        }

        async function fetchBoletoAlerts() {
            if (sessionStorage.getItem('cypher_auth') !== 'true') return;
            try {
                const res = await fetch('/api/boletos');
                const list = await res.json();
                renderBoletoAlerts(list);
            } catch (err) {
                console.error("Falha ao buscar avisos de boletos:", err);
            }
        }

        async function handleBoletoAction(id, action) {
            try {
                await fetch(`/api/boletos/${id}/action`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action })
                });
                fetchBoletoAlerts();
                fetchIncidents();
            } catch (err) {
                console.error("Falha ao atualizar ação do boleto:", err);
            }
        }

        async function toggleQuarantine(hostname) {
            await fetch(`/api/device/${hostname}/toggle`, { method: 'POST' });
            fetchDevices();
            fetchIncidents();
        }

        // Modal de Renomeação
        function openRenameModal(hostname, currentAlias) {
            document.getElementById('rename-hostname').value = hostname;
            document.getElementById('rename-display-hostname').value = hostname;
            document.getElementById('rename-alias').value = currentAlias || '';
            document.getElementById('rename-modal').classList.remove('hidden');
        }

        function closeRenameModal() {
            document.getElementById('rename-modal').classList.add('hidden');
        }

        async function handleRenameSubmit(e) {
            e.preventDefault();
            const hostname = document.getElementById('rename-hostname').value;
            const alias = document.getElementById('rename-alias').value;

            await fetch(`/api/device/${hostname}/rename`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ alias })
            });

            closeRenameModal();
            fetchDevices();
        }

        function renderDevices(devices) {
            const grid = document.getElementById('device-grid');
            document.getElementById('nav-count').innerText = devices.length;
            document.getElementById('stat-total').innerText = devices.length;

            const nowSecs = Math.floor(Date.now() / 1000);
            const normalCount = devices.filter(d => d.status === 'NORMAL' && (nowSecs - d.last_seen) <= 8).length;
            const quarantineCount = devices.filter(d => d.status === 'QUARENTENA').length;
            document.getElementById('stat-normal').innerText = normalCount;
            document.getElementById('stat-quarantine').innerText = quarantineCount;

            if (devices.length === 0) {
                grid.innerHTML = `
                    <div class="col-span-full py-20 text-center text-slate-500 border border-dashed border-surface-800 rounded-3xl bg-surface-900/40">
                        <svg class="w-10 h-10 mx-auto text-slate-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>
                        <p class="text-sm font-medium">Nenhum computador conectado no momento.</p>
                        <p class="text-xs text-slate-600 mt-1">Inicie o CYPHER Agent em um terminal Windows para registrá-lo automaticamente.</p>
                    </div>`;
                return;
            }

            grid.innerHTML = devices.map(d => {
                const isQuarantine = d.status === 'QUARENTENA';
                const displayName = d.alias ? d.alias : d.hostname;
                const subHostname = d.alias ? d.hostname : 'Hostname sem apelido';

                // Cálculo de Timeout do Heartbeat no Front-end
                const diffSecs = Math.max(0, nowSecs - d.last_seen);
                const isOffline = diffSecs > 8;
                const timeText = diffSecs < 60 ? `${diffSecs}s` : `${Math.floor(diffSecs / 60)}m`;

                const statusBadge = isOffline
                    ? `<span class="text-[11px] font-bold px-2.5 py-1 rounded-full border bg-slate-800/80 text-slate-400 border-slate-700">○ OFFLINE (${timeText})</span>`
                    : isQuarantine
                    ? `<span class="text-[11px] font-bold px-2.5 py-1 rounded-full border bg-rose-500/10 text-rose-400 border-rose-500/30">● EM QUARENTENA</span>`
                    : `<span class="text-[11px] font-bold px-2.5 py-1 rounded-full border bg-emerald-500/10 text-emerald-400 border-emerald-500/30">● PROTEGIDO</span>`;

                return `
                <div class="bg-surface-900 border ${isQuarantine ? 'border-rose-500/60 shadow-xl shadow-rose-500/10' : isOffline ? 'border-surface-800/60 opacity-80' : 'border-surface-800'} rounded-3xl p-6 flex flex-col justify-between shadow-lg transition-all">
                    <div>
                        <!-- Header do Card -->
                        <div class="flex justify-between items-start mb-4">
                            <div>
                                <div class="flex items-center gap-2">
                                    <h3 class="font-bold text-base text-white tracking-tight">${displayName}</h3>
                                    <button onclick="openRenameModal('${d.hostname}', '${d.alias || ''}')" title="Renomear dispositivo"
                                        class="text-slate-500 hover:text-cypher-base transition-colors">
                                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg>
                                    </button>
                                </div>
                                <p class="text-[11px] font-mono text-slate-500 mt-0.5">${subHostname}</p>
                            </div>
                            ${statusBadge}
                        </div>

                        <!-- IP em Destaque -->
                        <div class="bg-surface-950/90 border border-surface-800 rounded-2xl p-3.5 mb-4 flex items-center justify-between">
                            <span class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Endereço IP</span>
                            <span class="text-xs font-mono font-bold text-blue-400 bg-cypher-base/10 px-2.5 py-1 rounded-lg border border-cypher-base/20">${d.ip}</span>
                        </div>

                        <!-- Alerta ou Status de Proteção -->
                        ${isOffline ? `
                        <div class="mb-5 bg-surface-950/40 p-3 rounded-2xl text-xs text-slate-500 flex items-center gap-2 border border-surface-800/40">
                            <span class="w-2 h-2 rounded-full bg-slate-600"></span>
                            <span>Sem sinal do Agent há ${timeText}</span>
                        </div>` : d.last_alert ? `
                        <div class="mb-5 bg-rose-500/10 border border-rose-500/30 p-3.5 rounded-2xl text-xs text-rose-300">
                            <span class="font-bold block text-rose-400 mb-1">🚨 Violação Detectada:</span>
                            <span class="font-mono text-[11px]">${d.last_alert}</span>
                        </div>` : `
                        <div class="mb-5 bg-surface-950/40 p-3 rounded-2xl text-xs text-slate-400 flex items-center gap-2 border border-surface-800/40">
                            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                            <span>Integridade de arquivos preservada</span>
                        </div>`}
                    </div>

                    <!-- Botão de Ação -->
                    <button onclick="toggleQuarantine('${d.hostname}')" 
                        class="w-full py-3 px-4 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2 ${
                            isQuarantine 
                            ? 'bg-emerald-500 hover:bg-emerald-400 text-white shadow-lg shadow-emerald-500/20' 
                            : 'bg-rose-500/10 hover:bg-rose-500 text-rose-400 hover:text-white border border-rose-500/30'
                        }">
                        ${isQuarantine ? '<span>🔓 Liberar da Quarentena</span>' : '<span>🔒 Isolar Dispositivo</span>'}
                    </button>
                </div>`;
            }).join('');
        }

        function renderBoletoAlerts(list) {
            const tbody = document.getElementById('boletos-tbody');
            const totalEl = document.getElementById('stat-boletos-total');
            const fraudesEl = document.getElementById('stat-boletos-fraudes');
            const aprovadosEl = document.getElementById('stat-boletos-aprovados');
            const badgeCount = document.getElementById('boletos-count');

            // Filtra exclusivamente os boletos adulterados / com suspeita de fraude
            const boletosSuspeitos = list.filter(b => !b.confiavel || b.score_risco > 20);

            const bloqueadosCount = boletosSuspeitos.filter(b => b.status_auditoria === 'BLOQUEADO').length;
            const aprovadosCount = boletosSuspeitos.filter(b => b.status_auditoria === 'APROVADO').length;

            totalEl.innerText = boletosSuspeitos.length;
            fraudesEl.innerText = bloqueadosCount;
            aprovadosEl.innerText = aprovadosCount;
            badgeCount.innerText = boletosSuspeitos.filter(b => b.status_auditoria !== 'APROVADO').length;

            if (!boletosSuspeitos || boletosSuspeitos.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" class="text-center py-12 text-slate-500 font-sans">Nenhum aviso ou documento financeiro registrado até o momento.</td></tr>`;
                return;
            }

            tbody.innerHTML = boletosSuspeitos.map(b => {
                const statusAuditoria = b.status_auditoria || 'PENDENTE';
                
                let statusBadge = '';
                if (statusAuditoria === 'BLOQUEADO') {
                    statusBadge = `<span class="px-2.5 py-1 rounded-full text-[10px] font-bold border text-rose-400 bg-rose-500/10 border-rose-500/30">BLOQUEADO</span>`;
                } else if (statusAuditoria === 'APROVADO') {
                    statusBadge = `<span class="px-2.5 py-1 rounded-full text-[10px] font-bold border text-emerald-400 bg-emerald-500/10 border-emerald-500/30">AUDITADO</span>`;
                } else {
                    statusBadge = `<span class="px-2.5 py-1 rounded-full text-[10px] font-bold border text-amber-400 bg-amber-500/10 border-amber-500/30 animate-pulse">PENDENTE</span>`;
                }

                const dateStr = new Date(b.timestamp * 1000).toLocaleString('pt-BR');
                const nameDisplay = b.alias ? `${b.alias} (${b.hostname})` : b.hostname;
                const scoreColor = b.score_risco > 50 ? 'text-rose-400' : b.score_risco > 20 ? 'text-amber-400' : 'text-emerald-400';

                return `
                <tr class="hover:bg-surface-800/30 transition-colors">
                    <td class="py-3 px-4 font-bold text-slate-300">${b.id}</td>
                    <td class="py-3 px-4 text-slate-400">${dateStr}</td>
                    <td class="py-3 px-4">
                        <span class="text-white font-sans font-medium block">${nameDisplay}</span>
                        <span class="text-[11px] text-blue-400 font-mono">${b.ip}</span>
                    </td>
                    <td class="py-3 px-4 text-slate-200 font-mono">${b.arquivo}</td>
                    <td class="py-3 px-4 font-bold font-mono ${scoreColor}">${b.score_risco}/100</td>
                    <td class="py-3 px-4">${statusBadge}</td>
                    <td class="py-3 px-4 text-slate-300 font-sans text-xs max-w-xs truncate" title="${b.detalhes_alerta.join('; ')}">
                        ${b.detalhes_alerta.length > 0 ? b.detalhes_alerta.join('; ') : 'Documento sem divergências.'}
                    </td>
                    <td class="py-3 px-4 text-right">
                        <div class="flex items-center justify-end gap-1.5">
                            <button onclick="handleBoletoAction('${b.id}', 'bloquear')" 
                                class="px-2.5 py-1 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded-lg text-[11px] font-semibold transition-all">
                                ⛔ Bloquear
                            </button>
                            <button onclick="handleBoletoAction('${b.id}', 'auditar')" 
                                class="px-2.5 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg text-[11px] font-semibold transition-all">
                                ✓ Auditar
                            </button>
                        </div>
                    </td>
                </tr>`;
            }).join('');
        }

        function renderIncidents(list) {
            const tbody = document.getElementById('incidents-tbody');
            if (!list || list.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center py-12 text-slate-500 font-sans">Nenhuma ocorrência registrada até o momento.</td></tr>`;
                return;
            }

            tbody.innerHTML = list.map(inc => {
                const isIsolate = inc.event_type.includes('ISOLAMENTO') || inc.event_type.includes('QUARENTENA') || inc.event_type.includes('FRAUDE');
                const badgeColor = isIsolate ? 'text-rose-400 bg-rose-500/10 border-rose-500/30' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
                const dateStr = new Date(inc.timestamp * 1000).toLocaleString('pt-BR');
                const nameDisplay = inc.alias ? `${inc.alias} (${inc.hostname})` : inc.hostname;

                return `
                <tr class="hover:bg-surface-800/30 transition-colors">
                    <td class="py-3 px-4 font-bold text-slate-300">${inc.id}</td>
                    <td class="py-3 px-4 text-slate-400">${dateStr}</td>
                    <td class="py-3 px-4 text-white font-sans font-medium">${nameDisplay}</td>
                    <td class="py-3 px-4 text-blue-400 font-bold">${inc.ip}</td>
                    <td class="py-3 px-4">
                        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold border ${badgeColor}">
                            ${inc.event_type}
                        </span>
                    </td>
                    <td class="py-3 px-4 text-slate-300 font-sans text-xs">${inc.details}</td>
                </tr>`;
            }).join('');
        }

        setInterval(fetchDevices, 2500);
        setInterval(fetchBoletoAlerts, 3000);
        checkAuth();
    </script>
</body>
</html>"#)
}