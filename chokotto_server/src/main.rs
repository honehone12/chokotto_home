use std::path::PathBuf;
use tokio::{fs, net::ToSocketAddrs};
use salvo::prelude::*;
use tracing::{info, warn};
use anyhow::bail;

async fn check_dir() -> anyhow::Result<()> {
    let Some(mut download_dir) = dirs::home_dir() else {
        bail!("could not find home dir");
    };
    download_dir.push("Downloads");

    if !fs::try_exists(&download_dir).await? {
        info!("creating '{download_dir:?}' directory");
        fs::create_dir(&download_dir).await?;
    }

    Ok(())
}

fn local_listen_at() -> anyhow::Result<impl ToSocketAddrs + Send> {
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
    dest.push(format!("Downloads/{file_name}"));
    
    if !fs::try_exists(&dest).await? {
        return Ok(dest);
    }

    let Some(dest_str) = dest.to_str() else {
        bail!("os path is not supported to avoid overwrite");
    };
    let mut n = 1u32;
    loop {
        let mut new_dest_s = String::from(dest_str);
        let numbered = format!("({n})");
        match new_dest_s.find('.') {
            Some(idx) => {
                new_dest_s.insert_str(idx, &numbered);
            }
            None => {
                new_dest_s.push_str(&numbered);
            }
        }

        if !fs::try_exists(&new_dest_s).await? {
            return Ok(new_dest_s.into());
        }

        let (m, overflow) = n.overflowing_add(1);
        if overflow {
            bail!("could not make destination file");
        }
        n = m;
    }
}

#[handler]
async fn upload(req: &mut Request, res: &mut Response) {
    const FILE_KEY: &str = "file";
    
    let Some(file) = req.file(FILE_KEY).await else {
        warn!("no files were attached");
        bad_form(res);    
        return;
    };

    let Some(file_name) = file.name() else {
        warn!("could not find a file name");
        bad_form(res);
        return;
    };
    
    let dest = match make_dest(file_name).await {
        Ok(p) => p,
        Err(e) => {
            warn!("{e}");
            bad_form(res);
            return;
        }
    };
        
    match tokio::fs::copy(file.path(), &dest).await {
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

    check_dir().await?;

    let router = Router::new().get(index)
        .push(Router::with_path("upload").post(upload));

    let listen_at = local_listen_at()?;
    let listener = TcpListener::new(listen_at).bind().await;
    Server::new(listener).serve(router).await;

    Ok(())
}
