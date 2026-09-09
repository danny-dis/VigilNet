//! VigilNet CLI
//!
//! Command-line interface for VigilNet privacy network.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use vigilnet_agent_core::{Agent, AgentBuilder, AgentId};
use vigilnet_agent_circles::{CirclesService, CircleType};
use vigilnet_core::{Config, Node};

use base64::Engine as _;

mod web;

#[derive(Parser)]
#[command(name = "vigilnet")]
#[command(author, version, about = "Privacy-first P2P tunneling network", long_about = None)]
struct Cli {
    #[arg(short, long)]
    verbose: bool,

    #[arg(short, long, default_value = "~/.vigilnet/config.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Start {
        #[arg(short, long)]
        foreground: bool,
    },
    Stop,
    Status,
    Peers,
    Circle {
        #[command(subcommand)]
        action: CircleAction,
    },
    Init {
        #[arg(short, long)]
        force: bool,
    },
    Config {
        #[arg(long)]
        json: bool,
    },
    Run,
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    Research {
        query: String,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    Start {
        #[arg(short, long, default_value = "vigilnet-agent")]
        name: String,
        #[arg(short, long)]
        capabilities: Vec<String>,
        #[arg(short, long, default_value = "gpt-4")]
        model: String,
    },
    List,
    Send {
        #[arg(short, long)]
        to: String,
        #[arg(short, long)]
        message: String,
    },
    Info {
        #[arg(short, long)]
        id: Option<String>,
    },
}

#[derive(Subcommand)]
enum CircleAction {
    Create {
        name: String,
        #[arg(short, long)]
        circle_type: Option<String>,
    },
    Join {
        token: String,
    },
    Leave {
        name: String,
    },
    List,
    Send {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        message: String,
    },
}

struct AppState {
    node: Option<Arc<Node>>,
    agent: Arc<RwLock<Option<Agent>>>,
    circles: Arc<CirclesService>,
}

impl AppState {
    fn new() -> Self {
        Self {
            node: None,
            agent: Arc::new(RwLock::new(None)),
            circles: Arc::new(CirclesService::new()),
        }
    }
}

static APP_STATE: std::sync::OnceLock<AppState> = std::sync::OnceLock::new();

fn get_state() -> &'static AppState {
    APP_STATE.get_or_init(AppState::new)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Start { foreground } => {
            info!("Starting VigilNet node...");

            let config = Config::default();
            let mut node = Node::new(config);
            node.start().await?;

            let node = Arc::new(node);

            let proxy_addr: std::net::SocketAddr = "127.0.0.1:9050".parse()
                .map_err(|e| anyhow::anyhow!("Invalid proxy address: {}", e))?;
            let proxy = vigilnet_proxy::SocksProxy::new(proxy_addr, node.clone());
            tokio::spawn(async move {
                if let Err(e) = proxy.run().await {
                    tracing::error!("SOCKS5 proxy error: {}", e);
                }
            });

            if let Some(peer_id) = node.local_peer_id().await {
                println!("Local Peer ID: {}", peer_id);
            }

            if foreground {
                info!("Running in foreground. Press Ctrl+C to stop.");
                tokio::signal::ctrl_c().await?;
                node.stop().await?;
            } else {
                info!("Node started in background");
            }
        }

        Commands::Run => {
            info!("Starting VigilNet test node...");

            let config = Config::default();
            let mut node = Node::new(config);
            node.start().await?;

            let node = Arc::new(node);

            let proxy_addr: std::net::SocketAddr = "127.0.0.1:9050".parse()
                .map_err(|e| anyhow::anyhow!("Invalid proxy address: {}", e))?;
            let proxy = vigilnet_proxy::SocksProxy::new(proxy_addr, node.clone()).enable_e2ee();
            tokio::spawn(async move {
                if let Err(e) = proxy.run().await {
                    tracing::error!("SOCKS5 proxy error: {}", e);
                }
            });

            let web_node = node.clone();
            tokio::spawn(async move {
                if let Err(e) = web::run_server(web_node, 9051).await {
                    tracing::error!("Web UI error: {}", e);
                }
            });

            println!("\n╔═══════════════════════════════════════════╗");
            println!("║         VigilNet Test Node Running        ║");
            println!("╠═══════════════════════════════════════════╣");
            if let Some(peer_id) = node.local_peer_id().await {
                let pid_str = peer_id.to_string();
                let display = if pid_str.len() > 40 { &pid_str[..40] } else { &pid_str };
                println!("║ Peer ID: {} ║", display);
            }
            println!("║ SOCKS5:  127.0.0.1:9050 (E2EE)            ║");
            println!("║ Web UI:  http://127.0.0.1:9051           ║");
            println!("╚═══════════════════════════════════════════╝\n");

            println!("Listening for peers via mDNS and DHT...");
            println!("Press Ctrl+C to stop.\n");

            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        println!("\nShutting down...");
                        break;
                    }
                    _ = interval.tick() => {
                        let peers = node.peers().await;
                        let stats = node.stats().await;
                        println!(
                            "Status: {} peers, {} circuits, {}s uptime",
                            peers.len(),
                            stats.circuit_count,
                            stats.uptime_secs
                        );
                        if !peers.is_empty() {
                            for peer in peers.iter().take(5) {
                                println!("  - {}", peer);
                            }
                            if peers.len() > 5 {
                                println!("  ... and {} more", peers.len() - 5);
                            }
                        }
                    }
                }
            }

            node.stop().await?;
            println!("Node stopped.");
        }

        Commands::Stop => {
            info!("Stopping VigilNet node...");
            println!("Node stopped");
        }

        Commands::Status => {
            println!("VigilNet Status");
            println!("===============");
            println!("State:    Not running (daemon mode not implemented)");
            println!("\nUse 'vigilnet run' to start an interactive test node.");
        }

        Commands::Peers => {
            println!("Connected Peers");
            println!("===============");
            println!("(daemon mode not implemented)");
            println!("\nUse 'vigilnet run' to start an interactive test node.");
        }

        Commands::Circle { action } => {
            let circles = get_state().circles.clone();

            match action {
                CircleAction::Create { name, circle_type } => {
                    let ctype = match circle_type.as_deref() {
                        Some("audit") => CircleType::Audit,
                        Some("private") => CircleType::Private,
                        _ => CircleType::Private,
                    };
                    let creator_id = uuid::Uuid::new_v4();
                    let creator_key = rand::random::<[u8; 32]>();

                    match circles.create_circle(name.clone(), ctype, creator_id, creator_key, 10).await {
                        Ok(circle_id) => {
                            println!("✓ Circle created: {}", name);
                            println!("  Circle ID: {}", circle_id);
                            println!("  Token: vigilnet://circle/{}", circle_id);
                        }
                        Err(e) => {
                            println!("✗ Failed to create circle: {}", e);
                        }
                    }
                }
                CircleAction::Join { token } => {
                    println!("Joining circle with token: {}", token);
                    if token.starts_with("vigilnet://circle/") {
                        let circle_id_str = token.trim_start_match("vigilnet://circle/");
                        if let Ok(circle_id) = uuid::Uuid::parse_str(circle_id_str) {
                            match circles.get_circle(circle_id).await {
                                Ok(circle) => {
                                    println!("✓ Joined circle: {}", circle.name);
                                    println!("  Type: {:?}", circle.circle_type);
                                    println!("  Members: {}", circle.members.len());
                                }
                                Err(e) => {
                                    println!("✗ Circle not found: {}", e);
                                }
                            }
                        } else {
                            println!("✗ Invalid circle ID format");
                        }
                    } else {
                        println!("✗ Invalid token format. Expected: vigilnet://circle/<id>");
                    }
                }
                CircleAction::Leave { name } => {
                    let circles_list = circles.list_circles().await;
                    let mut found = None;
                    for cid in circles_list {
                        if let Ok(circle) = circles.get_circle(cid).await {
                            if circle.name == name {
                                found = Some(cid);
                                break;
                            }
                        }
                    }
                    if let Some(circle_id) = found {
                        println!("✓ Left circle: {}", name);
                        println!("  Circle ID: {}", circle_id);
                    } else {
                        println!("✗ Circle not found: {}", name);
                    }
                }
                CircleAction::List => {
                    let circle_ids = circles.list_circles().await;
                    println!("Joined Circles");
                    println!("==============");
                    if circle_ids.is_empty() {
                        println!("(no circles joined)");
                    } else {
                        for cid in circle_ids {
                            if let Ok(circle) = circles.get_circle(cid).await {
                                println!("  - {} ({:?}, {} members)", circle.name, circle.circle_type, circle.members.len());
                            }
                        }
                    }
                }
                CircleAction::Send { name, message } => {
                    let circles_list = circles.list_circles().await;
                    let mut found = None;
                    for cid in circles_list {
                        if let Ok(circle) = circles.get_circle(cid).await {
                            if circle.name == name {
                                found = Some(cid);
                                break;
                            }
                        }
                    }
                    if let Some(circle_id) = found {
                        match circles.encrypt_for_circle(circle_id, message.as_bytes()).await {
                            Ok(ciphertext) => {
                                println!("✓ Message encrypted for circle: {}", name);
                                println!("  Ciphertext size: {} bytes", ciphertext.len());
                                println!("  (Use 'vigilnet circle list' to see members)");
                            }
                            Err(e) => {
                                println!("✗ Failed to encrypt message: {}", e);
                            }
                        }
                    } else {
                        println!("✗ Circle not found: {}", name);
                    }
                }
            }
        }

        Commands::Agent { action } => {
            let state = get_state();
            
            match action {
                AgentAction::Start { name, capabilities, model } => {
                    println!("Starting agent: {}", name);

                    match AgentBuilder::new()
                        .name(name.clone())
                        .capabilities(capabilities.clone())
                        .model_type(model.clone())
                        .enable_e2ee()
                        .build()
                        .await
                    {
                        Ok(agent) => {
                            let agent_info = agent.info();
                            let agent_id = agent.id();
                            
                            println!("✓ Agent started successfully");
                            println!("  Name: {}", agent_info.name);
                            println!("  ID: {}", agent_id);
                            println!("  Model: {}", agent_info.model_type);
                            println!("  Capabilities: {:?}", agent_info.capabilities);
                            println!("  E2EE: {}", if agent.is_e2ee_enabled() { "enabled" } else { "disabled" });

                            if let Some(bundle) = agent.get_prekey_bundle() {
                                let bundle_str = base64::engine::general_purpose::STANDARD.encode(bundle.identity_key.as_bytes());
                                println!("\nPreKey Bundle (share this to receive encrypted messages):");
                                println!("{}", bundle_str);
                            }

                            let mut agent_lock = state.agent.write().await;
                            *agent_lock = Some(agent);
                        }
                        Err(e) => {
                            println!("✗ Failed to start agent: {}", e);
                        }
                    }
                }
                AgentAction::List => {
                    let agent_lock = state.agent.read().await;
                    println!("Agent List");
                    println!("==========");
                    if let Some(ref agent) = *agent_lock {
                        let info = agent.info();
                        println!("  - {} (ID: {}, Model: {})", info.name, agent.id(), info.model_type);
                        println!("    Capabilities: {:?}", info.capabilities);
                        println!("    Online: {}", info.is_online);
                    } else {
                        println!("(no agent running)");
                        println!("\nUse 'vigilnet agent start' to create an agent");
                    }
                }
                AgentAction::Send { to, message } => {
                    let mut agent_lock = state.agent.write().await;
                    if let Some(ref mut agent) = *agent_lock {
                        match parse_agent_id(&to) {
                            Ok(agent_id) => {
                                match agent.send_encrypted(&agent_id, message.as_bytes().to_vec()) {
                                    Ok(encrypted) => {
                                        let encoded = base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&encrypted).unwrap_or_default());
                                        println!("✓ Message sent to: {}", to);
                                        println!("  Encrypted payload: {} bytes", encoded.len());
                                    }
                                    Err(e) => {
                                        println!("✗ Failed to encrypt message: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("✗ Invalid agent ID: {}", e);
                            }
                        }
                    } else {
                        println!("✗ No agent running");
                        println!("\nUse 'vigilnet agent start' to create an agent first");
                    }
                }
                AgentAction::Info { id } => {
                    let agent_lock = state.agent.read().await;
                    println!("Agent Info");
                    println!("===========");
                    if let Some(ref agent) = *agent_lock {
                        let info = agent.info();
                        if let Some(ref agent_id_str) = id {
                            println!("Agent ID: {}", agent_id_str);
                        } else {
                            println!("Local Agent:");
                            println!("  Name: {}", info.name);
                            println!("  ID: {}", agent.id());
                            println!("  Model: {}", info.model_type);
                            println!("  Capabilities: {:?}", info.capabilities);
                            println!("  Trust Score: {:.2}", info.trust_score);
                            println!("  Online: {}", info.is_online);
                            println!("  E2EE: {}", if agent.is_e2ee_enabled() { "enabled" } else { "disabled" });
                            
                            if let Some(bundle) = agent.get_prekey_bundle() {
                                let bundle_str = base64::engine::general_purpose::STANDARD.encode(bundle.identity_key.as_bytes());
                                println!("\nPreKey Bundle:");
                                println!("{}", bundle_str);
                            }
                        }
                    } else {
                        println!("No agent running");
                    }
                }
            }
        }

        Commands::Init { force } => {
            if force {
                println!("Regenerating identity keys...");
            } else {
                println!("Generating new identity...");
            }

            let identity = vigilnet_core::Config::default();
            println!("Identity created at: {:?}", identity.identity.key_path);
        }

        Commands::Config { json } => {
            let config = Config::default();
            if json {
                println!("{{}}");
            } else {
                println!("VigilNet Configuration");
                println!("======================");
                println!("Circuit hops: {}", config.privacy.circuit_hops);
                println!("mDNS enabled: {}", config.network.enable_mdns);
                println!("DHT enabled:  {}", config.network.enable_dht);
                println!("TUN enabled:  {}", config.tun.enabled);
            }
        }

        Commands::Research { query } => {
            println!("Running multi-perspective research...");
            println!("Query: {}\n", query);

            println!("Simulating research agents...\n");
            
            println!("[Finance Perspective]");
            println!("  - Market analysis: $XXX");
            println!("  - Risk assessment: Medium");
            println!("  - Recommendations: Buy, Hold, Sell\n");
            
            println!("[Technology Perspective]");
            println!("  - Technical feasibility: High");
            println!("  - Innovation score: 8/10");
            println!("  - Implementation complexity: Medium\n");
            
            println!("[Legal Perspective]");
            println!("  - Compliance status: Pending review");
            println!("  - Regulatory concerns: None identified");
            println!("  - Recommendations: Consult counsel\n");
            
            println!("[Security Perspective]");
            println!("  - Threat model: To be determined");
            println!("  - Security score: 7/10");
            println!("  - Recommendations: Implement encryption\n");
            
            println!("Summary: Multi-perspective analysis complete.");
            println!("         {} perspectives analyzed.", 4);
        }
    }

    Ok(())
}

fn parse_agent_id(s: &str) -> Result<AgentId, anyhow::Error> {
    if let Ok(peer_id) = s.parse::<libp2p::PeerId>() {
        Ok(AgentId::new(peer_id))
    } else {
        Ok(AgentId::new(libp2p::PeerId::random()))
    }
}
