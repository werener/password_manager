mod commands;
mod error;
mod prompt;

use clap::{Parser, Subcommand};
use password_manager_client::{config, session};

#[derive(Parser)]
#[command(
    name = "passman",
    version,
    about = "Password manager CLI",
    disable_version_flag = true
)]
struct Cli {
    #[arg(short = 'v', short_alias = 'V', long = "version", action = clap::ArgAction::Version)]
    version: Option<bool>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set backend server URL
    Server {
        /// Server URL, e.g. http://localhost:3000
        url: Option<String>,
    },
    /// Show current configuration and session status
    Config,
    /// Register a new account
    Register {
        #[arg(long)]
        email: Option<String>,
        #[arg(
            long = "master",
            help = "Master password (discouraged: visible in shell history/process list; prefer interactive prompt)"
        )]
        master_password: Option<String>,
    },
    /// Login to an account
    Login {
        #[arg(long)]
        email: Option<String>,
        #[arg(
            long = "master",
            help = "Master password (discouraged: visible in shell history/process list; prefer interactive prompt)"
        )]
        master_password: Option<String>,
    },
    /// Logout from current account
    Logout,
    /// Add a credential
    Add {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long = "secret")]
        secret: Option<String>,
        #[arg(
            long = "master",
            help = "Master password (discouraged: visible in shell history/process list; prefer interactive prompt)"
        )]
        master_password: Option<String>,
    },
    /// List credentials
    List,
    /// Get a credential by id
    Get {
        id: Option<String>,
        #[arg(
            long = "master",
            help = "Master password (discouraged: visible in shell history/process list; prefer interactive prompt)"
        )]
        master_password: Option<String>,
    },
    /// Edit a credential by id
    Edit {
        id: Option<String>,
        #[arg(
            long = "master",
            help = "Master password (discouraged: visible in shell history/process list; prefer interactive prompt)"
        )]
        master_password: Option<String>,
    },
    /// Delete a credential by id
    Delete { id: Option<String> },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), error::CliError> {
    let paths = config::Paths::discover()?;

    match cli.command {
        Command::Server { url } => {
            let url = prompt::resolve_line(url, "Server URL: ")?;
            let url = url.trim().trim_end_matches('/').to_string();
            if url.is_empty() {
                return Err(error::CliError::Message(
                    "server URL cannot be empty".into(),
                ));
            }
            let mut cfg = config::Config::load(&paths.config)?;
            cfg.server_url = Some(url.clone());
            cfg.save(&paths.config)?;
            println!("server URL set to {url}");
        }
        Command::Config => {
            let cfg = config::Config::load(&paths.config)?;
            let sess = session::Session::load(&paths.session)?;
            println!("config_path: {}", paths.config.display());
            println!("session_path: {}", paths.session.display());
            println!(
                "server_url: {}",
                cfg.server_url.as_deref().unwrap_or("(not set)")
            );
            match sess {
                Some(s) => {
                    println!("email: {}", s.email);
                    println!("session: present");
                }
                None => {
                    println!("email: (none)");
                    println!("session: none");
                }
            }
        }
        Command::Register {
            email,
            master_password,
        } => commands::register(&paths, email, master_password).await?,
        Command::Login {
            email,
            master_password,
        } => commands::login(&paths, email, master_password).await?,
        Command::Logout => commands::logout(&paths).await?,
        Command::Add {
            name,
            username,
            url,
            notes,
            secret,
            master_password,
        } => commands::add(&paths, name, username, url, notes, secret, master_password).await?,
        Command::List => commands::list(&paths).await?,
        Command::Get {
            id,
            master_password,
        } => commands::get(&paths, id, master_password).await?,
        Command::Edit {
            id,
            master_password,
        } => commands::edit(&paths, id, master_password).await?,
        Command::Delete { id } => commands::delete(&paths, id).await?,
    }

    Ok(())
}
