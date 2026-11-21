use std::io::{self, IsTerminal, Write};

use crate::error::CliError;

pub fn prompt_line(label: &str) -> Result<String, CliError> {
    if !io::stdin().is_terminal() {
        return Err(CliError::Message(format!(
            "missing input: {label} (run interactively or pass it as a command argument)"
        )));
    }
    print!("{label}");
    io::stdout().flush().map_err(CliError::Io)?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(CliError::Io)?;
    Ok(buf.trim().to_string())
}

pub fn prompt_password(label: &str) -> Result<String, CliError> {
    if !io::stdin().is_terminal() {
        return Err(CliError::Message(format!(
            "missing input: {label} (run interactively or pass it as a command argument)"
        )));
    }
    rpassword::prompt_password(label).map_err(CliError::Io)
}

pub fn prompt_password_confirm() -> Result<String, CliError> {
    let pw = prompt_password("Master password: ")?;
    let confirm = prompt_password("Confirm master password: ")?;
    if pw != confirm {
        return Err(CliError::Message("passwords do not match".into()));
    }
    if pw.is_empty() {
        return Err(CliError::Message("password cannot be empty".into()));
    }
    Ok(pw)
}

pub fn resolve_line(value: Option<String>, label: &str) -> Result<String, CliError> {
    match value {
        Some(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => prompt_line(label),
    }
}

pub fn resolve_password(value: Option<String>, label: &str) -> Result<String, CliError> {
    match value {
        Some(v) if !v.is_empty() => Ok(v),
        _ => prompt_password(label),
    }
}
