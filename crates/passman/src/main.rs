mod commands;
mod error;
mod prompt;

use clap::{Parser, Subcommand};
use password_manager_client::{config, session};

#[derive(Parser)]
#[command(name = "passman", version, about = "Password manager CLI", disable_version_flag = true)]
struct Cli {
    #[arg(short = 'v', short_alias = 'V', long = "version", action = clap::ArgAction::Version)]
    version: Option<bool>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set backend server URL
    Server { url: String },
    /// Show current configuration and session status
    Config,
    /// Register a new account
    Register,
    /// Login to an account
    Login,
    /// Logout from current account
    Logout,
    /// Add a credential
    Add,
    /// List credentials
    List,
    /// Get a credential by id
    Get { id: String },
    /// Edit a credential by id
    Edit { id: String },
    /// Delete a credential by id
    Delete { id: String },
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
        Command::Register => commands::register(&paths).await?,
        Command::Login => commands::login(&paths).await?,
        Command::Logout => commands::logout(&paths).await?,
        Command::Add => commands::add(&paths).await?,
        Command::List => commands::list(&paths).await?,
        Command::Get { id } => commands::get(&paths, &id).await?,
        Command::Edit { id } => commands::edit(&paths, &id).await?,
        Command::Delete { id } => commands::delete(&paths, &id).await?,
    }

    Ok(())
}
