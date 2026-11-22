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
        /// Email address (same as --email)
        email: Option<String>,
        #[arg(long = "email", conflicts_with = "email")]
        email_opt: Option<String>,
    },
    /// Login to an account
    Login {
        /// Email address (same as --email)
        email: Option<String>,
        #[arg(long = "email", conflicts_with = "email")]
        email_opt: Option<String>,
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
    },
    /// List credentials
    List {
        /// Show credential IDs
        #[arg(long = "ids")]
        show_ids: bool,
    },
    /// Get a credential by id
    Get { id: Option<String> },
    /// Edit a credential by id
    Edit { id: Option<String> },
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
            let url = commands::server(&paths, url)?;
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
        Command::Register { email, email_opt } => {
            commands::register(&paths, email.or(email_opt)).await?
        }
        Command::Login { email, email_opt } => commands::login(&paths, email.or(email_opt)).await?,
        Command::Logout => commands::logout(&paths).await?,
        Command::Add {
            name,
            username,
            url,
            notes,
            secret,
        } => commands::add(&paths, name, username, url, notes, secret).await?,
        Command::List { show_ids } => commands::list(&paths, show_ids).await?,
        Command::Get { id } => commands::get(&paths, id).await?,
        Command::Edit { id } => commands::edit(&paths, id).await?,
        Command::Delete { id } => commands::delete(&paths, id).await?,
    }

    Ok(())
}
