use std::path::Path;
use reqwest::IntoUrl;
use tokio::fs::{self, File};
use clap::Parser;
use anyhow::bail;
use tracing::info;
use url::Url;

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[arg(short, long)]
    file: String,
    #[arg(short, long)]
    address: String
}

async fn check_file(path: impl AsRef<Path>) -> anyhow::Result<()> {
    if !fs::try_exists(&path).await? {
        bail!("could not find the file");
    }
    
    let file = File::open(path).await?;
    let meta = file.metadata().await?;
    if !meta.is_file() {
        bail!("the path is not file");
    }
    if meta.len() == 0 {
        bail!("the file is empty");
    }

    Ok(())
}

fn make_url(literal: &str, use_http3: bool) -> anyhow::Result<impl IntoUrl> {
    const TARGET_PORT: u16 = 4545;
    const HTTP: &str = "http";
    const HTTPS: &str = "https";

    let mut url = Url::parse(literal)?;
    let scheme = match use_http3 {
        true => HTTPS,
        false => HTTP
    };
    if url.set_scheme(scheme).is_err() {
        bail!("failed to set scheme");
    }
    if url.set_port(Some(TARGET_PORT)).is_err() {
        bail!("failed to set port");
    }

    Ok(url)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    
    check_file(&cli.file).await?;
    let url = make_url(&cli.address, false)?; 
    
    let client = reqwest::Client::new();
    
    

    Ok(())
}
