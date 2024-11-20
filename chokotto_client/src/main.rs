use std::{
    net::IpAddr, 
    path::{Path, PathBuf}, 
    str::FromStr
};
use reqwest::{multipart, Certificate, Client, IntoUrl, StatusCode, Version};
use tokio::fs::{self, File};
use clap::Parser;
use anyhow::bail;
use tracing::info;
use url::Url;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[arg(short, long)]
    file: PathBuf,
    #[arg(short, long)]
    address: String,
    #[arg(long = "no-https")]
    no_https: bool,
    #[arg(long)]
    http3: bool,
    #[arg(long = "cert-path", default_value = "../cert/server.crt")]
    cert_path: PathBuf
}

#[derive(Clone, Copy)]
enum RequestVersion {
    Http3,
    Http2,
    Http1NoTls
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

fn make_url(ip_addr: &str, no_https: bool) -> anyhow::Result<Url> {
    _ = IpAddr::from_str(ip_addr)?;
    
    const HTTP: &str = "http";
    const HTTPS: &str = "https";
    let scheme = match no_https {
        true => HTTP,
        false => HTTPS
    };

    const TARGET_PORT: u16 = 4545;
    let s = format!("{scheme}://{ip_addr}:{TARGET_PORT}");
    let url = Url::parse(&s)?;

    Ok(url)
}

async fn check_server_version(
    client: &Client,
    base_url: impl IntoUrl, 
    req_version: RequestVersion
) -> anyhow::Result<()> {
    let mut req = client.get(base_url);
    match req_version {
        RequestVersion::Http3 => req = req.version(Version::HTTP_3),
        RequestVersion::Http2 => req = req.version(Version::HTTP_2),
        RequestVersion::Http1NoTls => (),
    };

    let res = req.send().await?;
    let status = res.status();

    let msg = match res.text().await {
        Ok(m) => m,
        Err(e) => bail!("invalid response: {e}")
    };

    if !matches!(status, StatusCode::OK) {
        bail!("{msg}, version check failed with {status}");
    }

    if msg != env!("CARGO_PKG_VERSION") {
        bail!("server version is different from client");
    }

    Ok(())
}

async fn upload_file(
    client: &Client,
    base_url: impl IntoUrl,
    req_version: RequestVersion,
    file: impl AsRef<Path> 
) -> anyhow::Result<()> {
    const FILE_KEY: &str = "file";
    let form = multipart::Form::new().file(FILE_KEY, file).await?;
    let mut url = base_url.into_url()?;
    url.set_path("upload");
    
    let mut req = client.post(url).multipart(form);
    match req_version {
        RequestVersion::Http3 => req = req.version(Version::HTTP_3),
        RequestVersion::Http2 => req = req.version(Version::HTTP_2),
        RequestVersion::Http1NoTls => (),
    }

    let res = req.send().await?;

    let status = res.status();
    let msg = match res.text().await {
        Ok(m) => m,
        Err(e) => bail!("invalid response: {e}")
    };

    if !matches!(status, StatusCode::OK) {
        bail!("{msg}, request failed with status code {status}");
    }

    info!("{msg}, with status code {status}");
    Ok(())
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

    let mut client_builder = reqwest::Client::builder();
    if !cli.no_https {
        let cert = fs::read(cli.cert_path).await?;
        let cert = Certificate::from_pem(&cert)?;
        client_builder = client_builder.add_root_certificate(cert);
        
        client_builder = match cli.http3 {
            true => client_builder.http3_prior_knowledge(),
            false => client_builder.http2_prior_knowledge() 
        }
    }
    let client = client_builder.build()?;

    let base_url = make_url(&cli.address, cli.no_https)?; 
    let req_version = if cli.http3 {
        RequestVersion::Http3
    } else if !cli.no_https {
        RequestVersion::Http2
    } else {
        RequestVersion::Http1NoTls
    };    

    check_server_version(&client, base_url.clone(), req_version).await?;    
    
    upload_file(&client, base_url, req_version, cli.file).await?;

    Ok(())
}
