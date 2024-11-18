use std::{net::IpAddr, path::{Path, PathBuf}, str::FromStr};
use reqwest::{multipart, Certificate, StatusCode};
use tokio::fs::{self, File};
use clap::Parser;
use anyhow::bail;
use tracing::info;
use url::Url;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[arg(short, long)]
    file: String,
    #[arg(short, long)]
    address: String,
    #[arg(long = "no-https")]
    no_https: bool,
    #[arg(long)]
    http3: bool,
    #[arg(long = "cert-path", default_value = "../cert/server.crt")]
    cert_path: PathBuf
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

fn make_url(ip_addr: &str, no_tls: bool) -> anyhow::Result<Url> {
    _ = IpAddr::from_str(ip_addr)?;
    
    const HTTP: &str = "http";
    const HTTPS: &str = "https";
    let scheme = match no_tls {
        true => HTTP,
        false => HTTPS
    };

    const TARGET_PORT: u16 = 4545;
    let s = format!("{scheme}://{ip_addr}:{TARGET_PORT}");
    let url = Url::parse(&s)?;

    Ok(url)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let cli = Cli::parse();
    if cli.no_https && cli.http3 {
        bail!("http3 can not be used without https");
    }

    check_file(&cli.file).await?;
    let mut url = make_url(&cli.address, cli.no_https)?; 

    let mut client_builder = reqwest::Client::builder();
    if !cli.no_https {
        let cert = fs::read(cli.cert_path).await?;
        let cert = Certificate::from_pem(&cert)?;
        client_builder = client_builder.add_root_certificate(cert);
        
        if cli.http3 {
            client_builder = client_builder.http3_prior_knowledge();
        } else {
            client_builder = client_builder.http2_prior_knowledge();
        }
    }
    let client = client_builder.build()?;

    let res = client.get(url.clone()).send().await?;
    let status = res.status();     
    if !matches!(status, StatusCode::OK) {
        bail!("request error with status code {status}");
    }

    info!("response version {:?} ", res.version());

    let msg = match res.text().await {
        Ok(m) => m,
        Err(e) => {
            bail!("could not get server version, {e}")
        }
    };
    if msg != env!("CARGO_PKG_VERSION") {
        bail!("server version is different from client");
    }
    
    const FILE_KEY: &str = "file";
    let form = multipart::Form::new().file(FILE_KEY, cli.file).await?;
    url.set_path("upload");
    let res = client.post(url)
        .multipart(form)
        .send().await?;

    info!("response version {:?} ", res.version());
    let status = res.status();
    match res.text().await {
        Ok(msg) => info!("{msg}, request has done with status code {status}"),
        Err(_) => info!("request has done with status code {status}")
    }

    Ok(())
}
