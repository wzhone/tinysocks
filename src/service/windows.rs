use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{Context, Result};
use tinysocks::{
    config::{Config, RuntimeOptions},
    server::ProxyServer,
};

use super::{SERVICE_DESCRIPTION, windows_service_args};

static SERVICE_NAME: OnceLock<String> = OnceLock::new();
static SERVICE_OPTIONS: OnceLock<RuntimeOptions> = OnceLock::new();

const WINDOWS_SERVICE_NAME: &str = "TinySocks";
const DEFAULT_WINDOWS_APP_DIR_NAME: &str = "TinySocks";

/// Return the Windows install directory for the service binary.
fn install_dir() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
        .join(DEFAULT_WINDOWS_APP_DIR_NAME)
}

/// Return the installed executable path for a service name.
fn installed_exe_path(service_name: &str) -> PathBuf {
    install_dir().join(format!("{service_name}.exe"))
}

/// Install and start the Windows service.
pub(crate) fn install(options: &RuntimeOptions) -> Result<()> {
    use std::ffi::OsString;
    use std::fs;
    use windows_service::{
        service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let service_name = WINDOWS_SERVICE_NAME;
    let installed_exe = installed_exe_path(service_name);
    let current_exe = std::env::current_exe().context("Failed to locate current executable")?;

    if let Some(parent) = installed_exe.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create install directory {}", parent.display()))?;
    }
    if installed_exe.exists()
        && current_exe.canonicalize().ok() == installed_exe.canonicalize().ok()
    {
        println!("Binary is already installed at {}", installed_exe.display());
    } else {
        fs::copy(&current_exe, &installed_exe).with_context(|| {
            format!(
                "Failed to copy {} to {}",
                current_exe.display(),
                installed_exe.display()
            )
        })?;
    }

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)
        .context("Installing a service requires administrator privileges")?;
    let launch_arguments = windows_service_args(options)?
        .into_iter()
        .map(OsString::from)
        .collect();

    let service_info = ServiceInfo {
        name: OsString::from(service_name),
        display_name: OsString::from(service_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: installed_exe.clone(),
        launch_arguments,
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = service_manager
        .create_service(
            &service_info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .with_context(|| format!("Failed to create Windows service '{}'", service_name))?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .context("Failed to set Windows service description")?;
    service
        .start::<&std::ffi::OsStr>(&[])
        .with_context(|| format!("Failed to start Windows service '{}'", service_name))?;

    println!(
        "Installed service '{}' using {}; description: {}",
        service_name,
        installed_exe.display(),
        SERVICE_DESCRIPTION
    );
    Ok(())
}

/// Stop and remove the Windows service.
pub(crate) fn uninstall() -> Result<()> {
    use std::{
        thread::sleep,
        time::{Duration, Instant},
    };
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let service_name = WINDOWS_SERVICE_NAME;
    let installed_exe = installed_exe_path(service_name);
    let installed_dir = installed_exe.parent().map(Path::to_path_buf);

    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)
        .context("Uninstalling a service requires administrator privileges")?;
    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;

    let service = match service_manager.open_service(service_name, service_access) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => {
            println!("Service '{}' is not installed.", service_name);
            remove_install_files(&installed_exe, installed_dir.as_deref())?;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    if service.query_status()?.current_state != ServiceState::Stopped
        && let Err(err) = service.stop()
    {
        return Err(err.into());
    }
    service.delete()?;
    drop(service);

    let timeout = Duration::from_secs(5);
    let start = Instant::now();
    while start.elapsed() < timeout {
        match service_manager.open_service(service_name, ServiceAccess::QUERY_STATUS) {
            Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => {
                println!("Service '{}' removed.", service_name);
                remove_install_files(&installed_exe, installed_dir.as_deref())?;
                return Ok(());
            }
            _ => sleep(Duration::from_millis(250)),
        }
    }

    println!(
        "Service '{}' marked for deletion (will disappear once it stops).",
        service_name
    );
    remove_install_files(&installed_exe, installed_dir.as_deref())?;
    Ok(())
}

/// Remove installed service files when possible.
fn remove_install_files(installed_exe: &Path, installed_dir: Option<&Path>) -> Result<()> {
    use std::fs;

    match fs::remove_file(installed_exe) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("Failed to remove {}", installed_exe.display()));
        }
    }
    if let Some(installed_dir) = installed_dir {
        match fs::remove_dir(installed_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("Failed to remove {}", installed_dir.display()));
            }
        }
    }
    Ok(())
}

/// Start the Windows service dispatcher.
pub(crate) fn run_as_service(options: RuntimeOptions) -> Result<()> {
    use windows_service::service_dispatcher;

    let service_name = WINDOWS_SERVICE_NAME;
    SERVICE_NAME
        .set(service_name.to_string())
        .map_err(|_| anyhow::anyhow!("service already initialized"))?;
    SERVICE_OPTIONS
        .set(options)
        .map_err(|_| anyhow::anyhow!("runtime options already initialized"))?;

    service_dispatcher::start(service_name, ffi_service_main)
        .context("Failed to start service dispatcher")?;
    Ok(())
}

windows_service::define_windows_service!(ffi_service_main, windows_service_main);

/// Windows service entry point called by the service dispatcher.
fn windows_service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(err) = run_service_worker() {
        eprintln!("tinysocks service error: {:?}", err);
    }
}

/// Run the proxy worker inside the Windows service runtime.
fn run_service_worker() -> windows_service::Result<()> {
    use std::{io, time::Duration};
    use tokio::{runtime::Builder, sync::watch};
    use windows_service::{
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };

    let service_name = SERVICE_NAME
        .get()
        .expect("service name initialized")
        .clone();
    let options = SERVICE_OPTIONS
        .get()
        .expect("runtime options initialized")
        .clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let event_shutdown = shutdown_tx.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = event_shutdown.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(&service_name, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let runtime = Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| windows_service::Error::Winapi(io::Error::other(e)))?;

    let server_result = runtime.block_on(async move {
        let cfg = Config::from_runtime_options(options)?;
        let server = ProxyServer::new(cfg)?;
        server.run(Some(shutdown_rx)).await
    });

    drop(runtime);

    let exit_code = if server_result.is_ok() {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    server_result.map_err(|err| windows_service::Error::Winapi(io::Error::other(err.to_string())))
}
