use std::{net::IpAddr, path::{Path, PathBuf}};
use tokio::fs::{self, File};
use salvo::{conn::rustls::{Keycert, RustlsConfig}, prelude::*};
use tracing::{info, warn};
use anyhow::bail;

async fn check_save_dir() -> anyhow::Result<()> {
    let Some(mut download_dir) = dirs::home_dir() else {
        bail!("could not find home dir");
    };

    const DIR_NAME: &str = "Downloads";
    download_dir.push(DIR_NAME);

    if !fs::try_exists(&download_dir).await? {
        info!("creating '{download_dir:?}' directory");
        fs::create_dir(&download_dir).await?;
    }

    Ok(())
}

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
fn bad_form(res: &mut Response) {
    res.status_code(StatusCode::BAD_REQUEST);
    res.render("bad http form");
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
    let mut n = 1u32;
    loop {
        let mut new_dest = String::from(dest);
        let numbered = format!("({n})");
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
            || c == '_'  || c == '-'
            || c == '('  || c == ')'
            || c == '.'
    }) {
        bail!("invalid file name");
    }
    
    Ok(())
}

#[handler]
async fn upload(req: &mut Request, res: &mut Response) {
    const FILE_KEY: &str = "file";
    let Some(file) = req.file(FILE_KEY).await else {
        warn!("no files were attached");
        bad_form(res);    
        return;
    };

    let tmp_path = file.path();
    if let Err(e) = validate_file(tmp_path).await {
        warn!("{e}");
        bad_form(res);
        return;
    }

    let Some(file_name) = file.name() else {
        warn!("could not find a file name");
        bad_form(res);
        return;
    };
    if let Err(e) = validate_file_name(file_name) {
        warn!("{e}");
        bad_form(res);
        return;
    }
    
    let dest = match make_dest(file_name).await {
        Ok(p) => p,
        Err(e) => {
            warn!("{e}");
            bad_form(res);
            return;
        }
    };
        
    match tokio::fs::copy(tmp_path, &dest).await {
        Ok(n) =>  {
            info!("created {dest:?} {n}bytes");
            res.render("ok");
        }
        Err(e) =>  {
            warn!("{e}");
            bad_form(res);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();    

    check_save_dir().await?;

    let router = Router::new().get(index)
        .push(Router::with_path("upload").post(upload));

    let listen_at = local_listen_at()?;
    let key_cert = Keycert::new()
        .cert(include_bytes!("../../cert/server.crt"))
        .key(include_bytes!("../../cert/server.key"));
    let tls_config = RustlsConfig::new(key_cert);
    let tls_listener = TcpListener::new(listen_at).rustls(tls_config.clone());
    let quic_config = tls_config.build_quinn_config()?;
    let quic_listenr = QuinnListener::new(quic_config, listen_at)
        .join(tls_listener)
        .bind().await;

    Server::new(quic_listenr).serve(router).await;

    Ok(())
}

mod test {
    #[cfg(test)]
    use super::validate_file_name;

    #[test]
    fn test_validate_file_name() {
        assert!(validate_file_name("my_pic_11-11(9).jpg").is_ok());
        assert!("!#$%&'=~^|@`{[]}:*;+<>,/?\"\"\\ あいアイ甲乙".chars().all(|c| {
            validate_file_name(&c.to_string()).is_err()
        }));
    }
}