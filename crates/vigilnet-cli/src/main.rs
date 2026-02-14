//! VigilNet CLI
//!
//! Command-line interface for VigilNet privacy network.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use vigilnet_agent_core::{Agent, AgentBuilder, AgentId, AgentInfo};
use vigilnet_agent_circles::{CirclesService, CircleType};
use vigilnet_core::{Config, Node};
use vigilnet_crypto::PreKeyBundle;

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

#[derive(Subcommand)]
enum CircleAction {
    /// Create a new private circle
    Create {
        /// Circle name
        name: String,
    },
    /// Join an existing circle
    Join {
        /// Circle token
        token: String,
    },
    /// Leave a circle
    Leave {
        /// Circle name
        name: String,
    },
    /// List joined circles
    List,
}

struct AppState {
    node: Option<Arc<Node>>,
    agent: Option<Arc<RwLock<Option<Agent>>>>,
    circles: Option<Arc<CirclesService>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            node: None,
            agent: None,
            circles: Some(Arc::new(CirclesService::new())),
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

            let proxy_addr = "127.0.0.1:9050".parse().unwrap();
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

            let proxy_addr = "127.0.0.1:9050".parse().unwrap();
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
            let circles = get_state().circles.as_ref().expect("Circles service not initialized");

            match action {
                CircleAction::Create { name, circle_type } => {
                    let ctype = match circle_type.as_deref() {
                        Some("audit") => CircleType::Audit,
                        Some("private") => CircleType::Private,
                        _ => CircleType::Private,
                    };
                    let creator_id = uuid::Uuid::new_v4();
                    let creator_key = [0u8; 32];

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
                                    let circle = circle.read().await;
                                    println!("✓ Joined circle: {}", circle.name);
                                }
                                Err(e) => {
                                    println!("✗ Circle not found: {}", e);
                                }
                            }
                        }
                    } else {
                        println!("✗ Invalid token format");
                    }
                }
                CircleAction::Leave { name } => {
                    println!("Leaving circle: {}", name);
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
                                let c = circle.read().await;
                                println!("  - {} ({})", c.name, c.circle_type);
                            }
                        }
                    }
                }
                CircleAction::Send { name, message } => {
                    println!("Sending message to circle: {}", name);
                    println!("  Message: {}", message);
                }
            }
        }

        Commands::Agent { action } => {
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
                            println!("✓ Agent started successfully");
                            println!("  Name: {}", agent.info().name);
                            println!("  ID: {}", agent.id());
                            println!("  Model: {}", agent.info().model_type);
                            println!("  Capabilities: {:?}", agent.info().capabilities);
                            println!("  E2EE: {}", if agent.is_e2ee_enabled() { "enabled" } else { "disabled" });

                            if let Some(bundle) = agent.get_prekey_bundle() {
                                println!("\nPreKey Bundle (share this to receive encrypted messages):");
                                println!("{}", base64::encode(bundle.identity_key.as_bytes()));
                            }
                        }
                        Err(e) => {
                            println!("✗ Failed to start agent: {}", e);
                        }
                    }
                }
                AgentAction::List => {
                    println!("Agent List");
                    println!("==========");
                    println!("(Use 'vigilnet agent start' to create an agent)");
                }
                AgentAction::Send { to, message } => {
                    println!("Sending message to: {}", to);
                    println!("  Message: {}", message);
                }
                AgentAction::Info { id } => {
                    println!("Agent Info");
                    println!("===========");
                    if let Some(agent_id) = id {
                        println!("Agent ID: {}", agent_id);
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
    }

    Ok(())
}
