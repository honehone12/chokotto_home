use std::{net::IpAddr, path::Path, str::FromStr};
use reqwest::{multipart, Certificate, IntoUrl, Version};
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

fn make_url(ip_addr: &str, use_http3: bool) -> anyhow::Result<impl IntoUrl> {
    _ = IpAddr::from_str(ip_addr)?;
    
    let scheme = match use_http3 {
        true => HTTPS,
        false => HTTP
    };

    const TARGET_PORT: u16 = 4545;
    const HTTP: &str = "http";
    const HTTPS: &str = "https";
    
    let s = format!("{scheme}://{ip_addr}:{TARGET_PORT}");
    let mut url = Url::parse(&s)?;
    url.set_path("/upload");

    Ok(url)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    check_file(&cli.file).await?;
    let url = make_url(&cli.address, false)?; 
    
    let cert = Certificate::from_pem(include_bytes!("../../cert/server.crt"))?;
    let client = reqwest::Client::builder()
        .http3_prior_knowledge()
        .add_root_certificate(cert)
        .build()?;

    const FILE_KEY: &str = "file";
    let form = multipart::Form::new().file(FILE_KEY, cli.file).await?;
    let res = client.post(url)
        .version(Version::HTTP_3)
        .multipart(form)
        .send().await?;
    
    let status = res.status();
    match res.text().await {
        Ok(msg) => info!("{msg}, request has done with status code {status}"),
        Err(_) => info!("request has done with status code {status}")
    }

    Ok(())
}
