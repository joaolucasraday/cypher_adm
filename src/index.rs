use axum::{
    extract::{Path, State},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::cors::CorsLayer;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Device {
    pub hostname: String,
    pub ip: String,
    pub status: String,        // "NORMAL" ou "QUARENTENA"
    pub last_seen: u64,
    pub last_alert: Option<String>,
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

#[derive(Serialize)]
pub struct CommandResponse {
    pub should_isolate: bool,
}

type AppState = Arc<Mutex<HashMap<String, Device>>>;

#[tokio::main]
async fn main() {
    let state: AppState = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route("/", get(dashboard_handler))
        .route("/api/devices", get(get_devices))
        .route("/api/heartbeat", post(handle_heartbeat))
        .route("/api/alert", post(handle_alert))
        .route("/api/device/:hostname/toggle", post(toggle_quarantine))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    println!("=================================================");
    println!("     CYPHER ADM - PAINEL OPERACIONAL ATIVO       ");
    println!("     Acesse no navegador: http://localhost:8443 ");
    println!("=================================================");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Retorna lista de máquinas em JSON para o frontend
async fn get_devices(State(state): State<AppState>) -> Json<Vec<Device>> {
    let map = state.lock().unwrap();
    Json(map.values().cloned().collect())
}

// Recebe heartbeat do Agent e diz se ele deve estar isolado ou não
async fn handle_heartbeat(
    State(state): State<AppState>,
    Json(payload): Json<HeartbeatPayload>,
) -> Json<CommandResponse> {
    let mut map = state.lock().unwrap();
    let entry = map.entry(payload.hostname.clone()).or_insert_with(|| Device {
        hostname: payload.hostname.clone(),
        ip: payload.ip.clone(),
        status: "NORMAL".to_string(),
        last_seen: now_secs(),
        last_alert: None,
    });

    entry.last_seen = now_secs();
    entry.ip = payload.ip;

    Json(CommandResponse {
        should_isolate: entry.status == "QUARENTENA",
    })
}

// Recebe alerta crítico do Agent
async fn handle_alert(
    State(state): State<AppState>,
    Json(payload): Json<AlertPayload>,
) -> Json<serde_json::Value> {
    let mut map = state.lock().unwrap();
    if let Some(device) = map.get_mut(&payload.hostname) {
        device.status = "QUARENTENA".to_string();
        device.last_alert = Some(payload.details);
        println!("🚨 [ADM ALERTA] Dispositivo {} entrou em quarentena automática!", payload.hostname);
    }
    Json(serde_json::json!({ "status": "acknowledged" }))
}

// Botão de alternar Quarentena pelo Administrador
async fn toggle_quarantine(
    Path(hostname): Path<String>,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let mut map = state.lock().unwrap();
    if let Some(device) = map.get_mut(&hostname) {
        if device.status == "QUARENTENA" {
            device.status = "NORMAL".to_string();
            device.last_alert = None;
            println!("🔓 [ADM] Dispositivo {} liberado pelo operador.", hostname);
        } else {
            device.status = "QUARENTENA".to_string();
            device.last_alert = Some("Quarentena acionada manualmente pelo ADM".to_string());
            println!("🔒 [ADM] Dispositivo {} colocado em quarentena pelo operador.", hostname);
        }
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
    <title>CYPHER ADM — Centro de Operações</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        brand: { 950: '#06080e', 900: '#0b101b', 800: '#141c2e', 700: '#1f2a44' }
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-brand-950 text-slate-100 min-h-screen font-mono antialiased">
    <!-- Header -->
    <header class="border-b border-brand-700/60 bg-brand-900/50 backdrop-blur px-8 py-5 flex items-center justify-between">
        <div class="flex items-center space-x-3">
            <div class="h-3 w-3 rounded-full bg-emerald-500 animate-pulse"></div>
            <h1 class="text-xl font-bold tracking-widest text-emerald-400">CYPHER // ADM</h1>
            <span class="text-xs bg-brand-800 text-slate-400 px-2 py-0.5 rounded border border-brand-700">XDR CONTROL PLANE</span>
        </div>
        <div id="clock" class="text-xs text-slate-400"></div>
    </header>

    <!-- Main -->
    <main class="max-w-7xl mx-auto px-8 py-8">
        <div class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-lg font-bold text-slate-200">Dispositivos Conectados</h2>
                <p class="text-xs text-slate-500">Monitoramento ativo de endpoints na rede local</p>
            </div>
            <span id="endpoint-count" class="text-xs font-semibold px-3 py-1 bg-brand-800 border border-brand-700 rounded-full text-slate-300">0 computadores</span>
        </div>

        <!-- Grid de Cards de Computadores -->
        <div id="device-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div class="col-span-full py-16 text-center text-slate-600 border border-dashed border-brand-800 rounded-xl">
                Nenhum Agent conectado ainda. Inicie o Agent em uma máquina para visualizá-la aqui.
            </div>
        </div>
    </main>

    <script>
        function updateClock() {
            document.getElementById('clock').innerText = new Date().toLocaleTimeString('pt-BR');
        }
        setInterval(updateClock, 1000);
        updateClock();

        async function fetchDevices() {
            try {
                const res = await fetch('/api/devices');
                const devices = await res.json();
                renderDevices(devices);
            } catch (err) {
                console.error("Falha ao buscar dispositivos:", err);
            }
        }

        async function toggleQuarantine(hostname) {
            await fetch(`/api/device/${hostname}/toggle`, { method: 'POST' });
            fetchDevices();
        }

        function renderDevices(devices) {
            const grid = document.getElementById('device-grid');
            document.getElementById('endpoint-count').innerText = `${devices.length} computador(es)`;

            if (devices.length === 0) {
                grid.innerHTML = `
                    <div class="col-span-full py-16 text-center text-slate-600 border border-dashed border-brand-800 rounded-xl">
                        Nenhum Agent conectado ainda. Inicie o Agent em uma máquina para visualizá-la aqui.
                    </div>`;
                return;
            }

            grid.innerHTML = devices.map(d => {
                const isQuarantine = d.status === 'QUARENTENA';
                const statusBg = isQuarantine ? 'bg-rose-500/10 border-rose-500/30' : 'bg-emerald-500/10 border-emerald-500/30';
                const statusText = isQuarantine ? 'text-rose-400' : 'text-emerald-400';
                const dotColor = isQuarantine ? 'bg-rose-500 animate-ping' : 'bg-emerald-500';

                return `
                <div class="bg-brand-900 border ${isQuarantine ? 'border-rose-500/50' : 'border-brand-700'} rounded-xl p-6 flex flex-col justify-between shadow-lg relative overflow-hidden">
                    <div>
                        <div class="flex justify-between items-start mb-4">
                            <div>
                                <h3 class="font-bold text-base text-slate-100 flex items-center gap-2">
                                    <span class="h-2 w-2 rounded-full ${dotColor}"></span>
                                    ${d.hostname}
                                </h3>
                                <p class="text-xs text-slate-500 mt-0.5">IP: ${d.ip}</p>
                            </div>
                            <span class="text-xs font-bold px-2.5 py-1 rounded border ${statusBg} ${statusText}">
                                ${d.status}
                            </span>
                        </div>

                        ${d.last_alert ? `
                        <div class="mb-4 bg-rose-950/40 border border-rose-800/50 p-3 rounded text-xs text-rose-300">
                            <span class="font-bold">Incidente:</span> ${d.last_alert}
                        </div>` : `
                        <div class="mb-4 bg-brand-800/40 p-3 rounded text-xs text-slate-400">
                            Nenhum incidente detectado no momento.
                        </div>`}
                    </div>

                    <button onclick="toggleQuarantine('${d.hostname}')" 
                        class="w-full mt-2 py-2.5 px-4 rounded text-xs font-bold transition-colors ${
                            isQuarantine 
                            ? 'bg-emerald-600 hover:bg-emerald-500 text-white' 
                            : 'bg-rose-600 hover:bg-rose-500 text-white'
                        }">
                        ${isQuarantine ? '🔓 LIBERAR DA QUARENTENA' : '🔒 ISOLAR DISPOSITIVO'}
                    </button>
                </div>`;
            }).join('');
        }

        setInterval(fetchDevices, 2000);
        fetchDevices();
    </script>
</body>
</html>"#)
}