use std::path::Path;
use tokio::{
    sync::mpsc,
    time::{sleep, Duration},
};

use crate::{
    config,
    filter::{types::FilterError, DomainFilter},
};

pub async fn start_watching(filter: &DomainFilter) -> Result<(), FilterError> {
    let (tx, mut rx) = mpsc::channel(100);
    let filter_path = config::get_filters_path().map_err(FilterError::ConfigError)?;
    let filter_clone = filter.clone();

    tokio::spawn(async move {
        if let Err(e) = setup_file_watcher(&filter_path, tx) {
            tracing::error!(error=?e, "Failed to set up filter file watcher");
            return;
        }

        loop {
            sleep(Duration::from_secs(1)).await;
        }
    });

    tokio::spawn(async move {
        const DEBOUNCE_DURATION: Duration = Duration::from_millis(500);

        while rx.recv().await.is_some() {
            if !debounce_events(&mut rx, DEBOUNCE_DURATION).await {
                return; // Channel closed
            }

            if let Err(e) = filter_clone.reload().await {
                tracing::error!(error=?e, "Failed to reload filters");
            } else {
                tracing::debug!("Filter files changed, reloaded automatically");
            }
        }
    });

    Ok(())
}

fn setup_file_watcher(
    filter_path: &Path,
    tx: tokio::sync::mpsc::Sender<()>,
) -> Result<(), notify::Error> {
    use notify::{Event, EventKind, RecursiveMode, Watcher};

    let tx_clone = tx.clone();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            if matches!(
                event.kind,
                EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
            ) {
                for path in &event.paths {
                    if path.extension().and_then(|s| s.to_str()) == Some("list") {
                        if let Err(e) = tx_clone.try_send(()) {
                            tracing::error!(error=?e, "Failed to send filter change event");
                        }
                        break;
                    }
                }
            }
        }
    })?;

    watcher.watch(filter_path, RecursiveMode::NonRecursive)?;
    tracing::debug!(path=%filter_path.display(), "Started watching for filter changes");

    std::mem::forget(watcher);

    Ok(())
}

async fn debounce_events(rx: &mut tokio::sync::mpsc::Receiver<()>, duration: Duration) -> bool {
    loop {
        match tokio::time::timeout(duration, rx.recv()).await {
            Ok(Some(())) => {
                // Got another event, continue draining
            }
            Ok(None) => {
                // Channel closed
                return false;
            }
            Err(_) => {
                // Timeout reached, no more events
                return true;
            }
        }
    }
}
