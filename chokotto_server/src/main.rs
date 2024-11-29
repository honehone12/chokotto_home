use std::{
    net::IpAddr, 
    path::{Path, PathBuf}
};
use tokio::fs::{self, File};
use salvo::{
    conn::rustls::{Keycert, RustlsConfig}, 
    prelude::*, 
    routing::PathFilter, 
    serve_static::StaticDir
};
use clap::Parser;
use tracing::{info, warn};
use anyhow::bail;

#[derive(Parser)]
#[command(version)]
struct Args {
    #[arg(long = "no-https")]
    no_https: bool,
    #[arg(long = "cert-path", default_value = "../cert/server.crt")]
    cert_path: PathBuf,
    #[arg(long = "key-path", default_value = "../cert/server.key")]
    key_path: PathBuf
}

async fn check_dir(dir_name: &str) -> anyhow::Result<PathBuf> {
    let Some(mut dir) = dirs::home_dir() else {
        bail!("could not find home dir");
    };

    dir.push(dir_name);
    if !fs::try_exists(&dir).await? {
        info!("creating {dir:?} directory");
        fs::create_dir(&dir).await?;
    }

    Ok(dir)
}

#[inline]
async fn check_save_dir() -> anyhow::Result<PathBuf> {
    const SAVE_DIR: &str = "Downloads";
    check_dir(SAVE_DIR).await
}

#[inline]
async fn check_public_dir() -> anyhow::Result<PathBuf> {
    const PUB_DIR: &str = "Public";
    check_dir(PUB_DIR).await
}

#[inline]
fn local_listen_at() -> anyhow::Result<(IpAddr, u16)> {
    let local_ip = local_ip_address::local_ip()?;
    const LISTEN_PORT: u16 = 4545;
    
    Ok((local_ip, LISTEN_PORT))
}

#[handler]
async fn index(res: &mut Response) {
    res.render(env!("CARGO_PKG_VERSION"));
}

#[inline]
fn bad_form(res: &mut Response, warn: &str) -> anyhow::Result<()> {
    warn!(warn);
    res.status_code(StatusCode::BAD_REQUEST);
    res.render("bad http form");
    Ok(())
}

async fn make_dest(file_name: &str) -> anyhow::Result<PathBuf> {
    let Some(mut dest) = dirs::home_dir() else {
        bail!("could not find home dir");
    };

    const DIR_NAME: &str = "Downloads";
    dest.push(format!("{DIR_NAME}/{file_name}"));
    
    if !fs::try_exists(&dest).await? {
        return Ok(dest);
    }

    let Some(dest) = dest.to_str() else {
        bail!("os path is not supported to avoid overwrite");
    };
    let mut n = 0u32;
    loop {
        let mut new_dest = String::from(dest);
        let numbered = format!("_copy{n}");
        match new_dest.find('.') {
            Some(idx) => {
                new_dest.insert_str(idx, &numbered);
            }
            None => {
                new_dest.push_str(&numbered);
            }
        }

        if !fs::try_exists(&new_dest).await? {
            return Ok(new_dest.into());
        }

        let (m, overflow) = n.overflowing_add(1);
        if overflow {
            bail!("could not make destination file");
        }
        n = m;
    }
}

async fn validate_file(path: impl AsRef<Path>) -> anyhow::Result<()> {
    let file = File::open(path).await?;
    let meta = file.metadata().await?;
    if !meta.is_file() {
        bail!("received non-standard file");
    }
    if meta.len() == 0{
        bail!("the file is empty");
    }
    
    Ok(())
}

fn validate_file_name(name: &str) -> anyhow::Result<()> {
    const MAX_LEN: usize = 25;
    if name.len() == 0 || name.len() > MAX_LEN {
        bail!("invalid file name length");
    } 

    if !name.chars().all(|c| {
        c.is_ascii_alphanumeric() 
            || c == '_'  
            || c == '.'
    }) {
        bail!("invalid file name");
    }

    if name.find("..").is_some() {
        bail!("invalid file name");
    }
    
    Ok(())
}

#[handler]
async fn upload(req: &mut Request, res: &mut Response) 
-> anyhow::Result<()> {
    const FILE_KEY: &str = "file";
    let Some(file) = req.file(FILE_KEY).await else {
        return bad_form(res, "no files were attached");
    };

    let tmp_path = file.path();
    if let Err(e) = validate_file(tmp_path).await {
        return bad_form(res, &e.to_string());
    }

    let Some(file_name) = file.name() else {
        return bad_form(res, "could not find a file name");
    };
    if let Err(e) = validate_file_name(file_name) {
        return bad_form(res, &e.to_string());
    }
    
    let dest = match make_dest(file_name).await {
        Ok(p) => p,
        Err(e) => {
            return bad_form(res, &e.to_string());
        }
    };

    match tokio::fs::copy(tmp_path, &dest).await {
        Ok(n) =>  {
            info!("created {dest:?} {n}bytes, http version {:?}", req.version());
            res.render("ok");
            Ok(())
        }
        Err(e) =>  {
           return bad_form(res, &e.to_string());
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let args = Args::parse();

    check_save_dir().await?;
    let pub_dir = check_public_dir().await?;

    const UPLOAD_ROUTE: &str = "upload";
    const DOWNLOAD_ROUTE: &str = "download";
    let r = regex::Regex::new(r"^[a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*$")?;
    PathFilter::register_wisp_regex("file", r);
    let router = Router::new().get(index)
        .push(Router::with_path(UPLOAD_ROUTE).post(upload))
        .push(
            Router::with_path(format!("{DOWNLOAD_ROUTE}/<**name:file>")).get(
                StaticDir::new(pub_dir).include_dot_files(true)
            )
        );

    let listen_at = local_listen_at()?;

    if args.no_https {
        let tcp_listener = TcpListener::new(listen_at).bind().await;
        Server::new(tcp_listener).serve(router).await;

        return Ok(())
    }

    let cert = fs::read(args.cert_path).await?;
    let key = fs::read(args.key_path).await?;
    let key_cert = Keycert::new().cert(cert).key(key);
    let tls_config = RustlsConfig::new(key_cert);
    let tls_listener = TcpListener::new(listen_at).rustls(tls_config.clone());
    let quic_config = tls_config.build_quinn_config()?;
    let quic_listenr = QuinnListener::new(quic_config, listen_at)
        .join(tls_listener)
        .bind().await;
    Server::new(quic_listenr).serve(router).await;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::validate_file_name;
    use regex::Regex;

    #[test]
    fn test_validate_file_name() {
        assert!(validate_file_name("my_pic_11_14.jpg").is_ok());
        assert!("!#$%&'()-=~^|@`{[]}:*;+<>,/?\"\\ あいアイ愛¥".chars().all(|c| {
            validate_file_name(&c.to_string()).is_err()
        }));
        assert!(validate_file_name("..like...this").is_err());
    }

    #[test]
    fn test_regex_file_name() {
        const R: &str = r"^[a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*$";
        let regex = match Regex::new(R) {
            Ok(r) => r,
            Err(e) => panic!("{e}")
        };
        assert!(regex.is_match("my_av_1_9.mp4"));
        assert!(regex.is_match(".tonight.fun.av"));
        assert!("!#$%&'()-=~^|@`{[]}:*;+<>,/?\"\\ あいアイ愛¥".chars().all(|c| {
            !regex.is_match(&c.to_string())            
        }));
        assert!(!regex.is_match("..oh...good"));
    }
}