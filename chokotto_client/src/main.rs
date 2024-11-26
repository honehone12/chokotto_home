use std::{
    net::IpAddr, 
    path::{Path, PathBuf}, 
    str::FromStr, 
    time::SystemTime
};
use reqwest::{
    multipart, Certificate, Client, 
    IntoUrl, StatusCode, Version
};
use tokio::{fs::{self, File}, io::{AsyncWriteExt, BufWriter}};
use futures_util::StreamExt;
use clap::{Parser, ValueEnum, Subcommand};
use anyhow::bail;
use tracing::info;
use url::Url;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(short, long)]
    address: String,
    #[arg(value_enum, default_value_t = HttpMajor::Http3)]
    http_major: HttpMajor,
    #[arg(long = "cert-path", default_value = "../cert/server.crt")]
    cert_path: PathBuf
}

#[derive(Subcommand, Clone, Debug)]
enum Command {
    Upload {
        #[arg(short, long)]
        file: PathBuf
    },
    Download {
        #[arg(short, long)]
        file: PathBuf
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum HttpMajor {
    Http3,
    Http2,
    Http1,
    NoHttps
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

fn make_base_url(ip_addr: &str, http_major: HttpMajor) -> anyhow::Result<Url> {
    // just want check ip_addr can parsed as IpAddr
    _ = IpAddr::from_str(ip_addr)?;
    
    let scheme = match http_major {
        HttpMajor::NoHttps => "http",
        _ => "https"
    };

    const TARGET_PORT: u16 = 4545;
    let s = format!("{scheme}://{ip_addr}:{TARGET_PORT}");
    let url = Url::parse(&s)?;

    Ok(url)
}

async fn check_server_version(
    client: &Client,
    base_url: impl IntoUrl, 
    http_major: HttpMajor
) -> anyhow::Result<()> {
    let req = client.get(base_url).version(match http_major {
        HttpMajor::Http3 => Version::HTTP_3,
        HttpMajor::Http2 => Version::HTTP_2,
        _ => Version::HTTP_11
    });

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
    http_major: HttpMajor,
    file: impl AsRef<Path> 
) -> anyhow::Result<()> {
    check_file(&file).await?;

    const FILE_KEY: &str = "file";
    let form = multipart::Form::new().file(FILE_KEY, file).await?;
    let mut url = base_url.into_url()?;
    const UPLOAD_PATH: &str = "upload";
    url.set_path(UPLOAD_PATH);
    
    let req = client.post(url)
        .multipart(form)
        .version(match http_major {
            HttpMajor::Http3 => Version::HTTP_3,
            HttpMajor::Http2 => Version::HTTP_2,
            _ => Version::HTTP_11
        });

    let res = req.send().await?;

    let status = res.status();
    let version = res.version();
    let msg = match res.text().await {
        Ok(m) => m,
        Err(e) => bail!("invalid response: {e}")
    };
    if !matches!(status, StatusCode::OK) {
        bail!("{msg}, request failed with status code {status}");
    }

    info!("{msg}, with status code {status}, http version {version:?}");
    Ok(())
}

async fn download_file(
    client: &Client,
    base_url: impl IntoUrl,
    http_major: HttpMajor,
    file_name: &str
) -> anyhow::Result<()> {
    if fs::try_exists(file_name).await? {
        bail!("file already exists");
    }

    let mut url = base_url.into_url()?;
    const DOWNLOAD_PATH: &str = "download"; 
    url.set_path(&format!("{DOWNLOAD_PATH}/{file_name}"));

    let req = client.get(url).version(match http_major {
        HttpMajor::Http3 => Version::HTTP_3,
        HttpMajor::Http2 => Version::HTTP_2,
        _ => Version::HTTP_11
    });

    let res = req.send().await?;
    let status = res.status();
    if !matches!(status, StatusCode::OK) {
        bail!("could not find a file");
    }
    
    let version = res.version();
    let Some(content_type) = res.headers().get("content-type") else {
        bail!("invalid response header");
    };
    let content_type = match content_type.to_str() {
        Ok(s) => s.to_string(),
        Err(e) => bail!("invalid response header: {e}")
    };
    
    let mut read_stream = res.bytes_stream();

    let file = File::create_new(file_name).await?;
    let mut write_stream = BufWriter::new(file);
    let mut written = 0;

    // while let Some(chunk) = res.chunk().await? {
    //     written += write_stream.write(&chunk).await?;
    // }

    while let Some(frame) = read_stream.next().await{
        written += write_stream.write(&frame?).await?;
    }

    write_stream.flush().await?;
    info!(
        "created {file_name} {written}bytes, \
        content type {content_type}, \
        http version {version:?}"
    );
    
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let start_at = SystemTime::now();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let cli = Cli::parse();

    let mut client_builder = reqwest::Client::builder();
    if !matches!(cli.http_major, HttpMajor::NoHttps) {
        let cert = fs::read(cli.cert_path).await?;
        let cert = Certificate::from_pem(&cert)?;
        client_builder = client_builder.add_root_certificate(cert);
    }
    client_builder = match cli.http_major {
        HttpMajor::Http3 => client_builder.http3_prior_knowledge(),
        HttpMajor::Http2 => client_builder.http2_prior_knowledge(),
        _ => client_builder.http1_only(),
    };
    let client = client_builder.build()?;
    let base_url = make_base_url(&cli.address, cli.http_major)?; 

    check_server_version(&client, base_url.clone(), cli.http_major).await?;

    match cli.command {
        Command::Upload { file } => {
            upload_file(&client, base_url, cli.http_major, file).await?;
        }
        Command::Download { file } => {
            let Some(file) = file.to_str() else {
                bail!("invalid file name")
            };
            download_file(&client, base_url, cli.http_major, file).await?;
        }
    }

    let mil = SystemTime::now().duration_since(start_at)?.as_millis(); 
    info!("operation took {mil}milsecs");
    Ok(())
}
