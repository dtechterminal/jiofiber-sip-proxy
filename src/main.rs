mod admin;
mod bridge;
mod config;
mod diagnostic;
mod digest;
mod invite;
mod ont;
mod provisioner;
mod rtp;
mod sdp;
mod sip;
mod upstream;

use std::{env, path::Path, process::ExitCode};

use anyhow::{Result, bail};
use config::{Device, Network, SipConfig};

const USAGE: &str = "Usage: jiofiber-sip-proxy [bridge | provision | call NUMBER [WAV_PATH]]";

/// Obtain the SIP credentials by provisioning natively against Jio. The device serial and
/// TR-069 password are read from the ONT over telnet when `ONT_HOST` is set, so the user
/// supplies nothing about the device; explicit `DEVICE_SERIAL` / `TR069_PASSWORD` env vars
/// override anything discovered, and cover the case where the ONT can't be reached. The SIP
/// password always comes from provisioning — it rotates, so it is never read from the env.
async fn provision() -> Result<SipConfig> {
    let discovery = match ont::Ont::candidates_from_env()? {
        Some(targets) => match ont::discover(&targets).await {
            Ok(found) => {
                if let Some(user) = &found.auth_user {
                    eprintln!("ONT: logged in over telnet as {user}");
                }
                if let Some(serial) = &found.serial {
                    eprintln!(
                        "ONT: discovered serial {serial} (model {})",
                        found.model.as_deref().unwrap_or("unknown")
                    );
                }
                if found.tr069_password.is_some() {
                    eprintln!("ONT: read the TR-069 password from the device");
                }
                Some(found)
            }
            Err(error) => {
                eprintln!(
                    "warning: could not read config from the ONT ({error:#}); \
                     falling back to DEVICE_SERIAL / TR069_PASSWORD"
                );
                None
            }
        },
        None => None,
    };
    let (serial, model, password) = match discovery {
        Some(d) => (d.serial, d.model, d.tr069_password),
        None => (None, None, None),
    };
    let device = Device::resolve(serial, model, password)?;
    provisioner::provision(&device, config::insecure_tls()?).await
}

async fn shutdown() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = terminate.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}

async fn run() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let (command, call) = match args.as_slice() {
        [] => ("bridge", None),
        [arg] if matches!(arg.as_str(), "-h" | "--help") => {
            println!("{USAGE}");
            return Ok(());
        }
        [arg] if matches!(arg.as_str(), "bridge" | "provision") => (arg.as_str(), None),
        [arg, number] if arg == "call" => {
            ("call", Some((number.as_str(), "/tmp/jio_recording.wav")))
        }
        [arg, number, path] if arg == "call" => ("call", Some((number.as_str(), path.as_str()))),
        _ => bail!("{USAGE}"),
    };
    if command == "provision" {
        provision().await?.print();
        return Ok(());
    }
    if let Some((number, path)) = call {
        let network = Network::from_env()?;
        let cfg = provision().await?;
        let instance = network.instance.clone().unwrap_or_else(gen_instance);
        return diagnostic::call(&cfg, &network, &instance, number, Path::new(path)).await;
    }
    run_bridge().await
}

fn gen_instance() -> String {
    format!("<urn:uuid:{}>", uuid::Uuid::new_v4())
}

/// Run the bridge under a supervisor: it provisions, optionally disables the ONT's voice,
/// serves the line, and — when the admin UI applies new config — re-provisions and
/// re-registers in place without a process restart.
async fn run_bridge() -> Result<()> {
    let config_file = admin::config_file_path();
    let reload = std::sync::Arc::new(tokio::sync::Notify::new());
    let mut admin_up = false;
    if let Some(server) = admin::Admin::from_env()? {
        let server = std::sync::Arc::new(server);
        let reload = reload.clone();
        tokio::spawn(async move {
            if let Err(error) = server.serve(reload).await {
                eprintln!("admin server stopped: {error:#}");
            }
        });
        admin_up = true;
    }
    loop {
        admin::load_config_file(&config_file);
        let cfg = match provision().await {
            Ok(cfg) => cfg,
            // Without the admin UI there is no way to fix the config at runtime, so a
            // provisioning failure is fatal as before. With it up, stay alive and wait for
            // the operator to apply working config through the UI instead of crash-looping.
            Err(error) if !admin_up => return Err(error),
            Err(error) => {
                eprintln!("provisioning failed: {error:#}");
                eprintln!("waiting for configuration from the admin UI…");
                tokio::select! {
                    _ = reload.notified() => continue,
                    _ = shutdown() => return Ok(()),
                }
            }
        };
        // Take over the line: stop the ONT's own SIP so it does not fight us for the IMS
        // registration. Only runs when ONT_HOST is set; a failure is non-fatal.
        let keep_voice = config::optional("ONT_DISABLE_VOICE")
            .is_some_and(|v| v == "0" || v.eq_ignore_ascii_case("false"));
        if !keep_voice && let Some(targets) = ont::Ont::candidates_from_env()? {
            match ont::disable_voice(&targets).await {
                Ok(status) => eprintln!("ONT voice disabled: {status}"),
                Err(error) => eprintln!("warning: could not disable ONT voice: {error:#}"),
            }
        }
        let network = Network::from_env()?;
        let instance = network.instance.clone().unwrap_or_else(gen_instance);
        tokio::select! {
            result = bridge::serve(&cfg, &network, &instance) => return result,
            _ = reload.notified() => {
                eprintln!("config changed — re-provisioning and re-registering");
                continue;
            }
            _ = shutdown() => return Ok(()),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
