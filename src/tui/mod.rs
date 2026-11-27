//! Terminal UI: event loop and rendering.

mod app;
mod input;
mod view;

use std::time::Duration;

use anyhow::Result;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::DefaultTerminal;
use tokio::sync::mpsc;

use pass_sworm::config::Config;
use pass_sworm::device::DeviceIdentity;
use pass_sworm::store::VaultStore;

use app::{App, Msg};

/// Run the UI until the user quits. Restores the terminal on the way out,
/// including on errors.
pub fn run(cfg: Config, store: VaultStore, device: DeviceIdentity) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
        let mut terminal = ratatui::init();
        let result = event_loop(&mut terminal, cfg, store, device, tx, &mut rx).await;
        ratatui::restore();
        result
    })
}

async fn event_loop(
    terminal: &mut DefaultTerminal,
    cfg: Config,
    store: VaultStore,
    device: DeviceIdentity,
    tx: mpsc::UnboundedSender<Msg>,
    rx: &mut mpsc::UnboundedReceiver<Msg>,
) -> Result<()> {
    let mut app = App::new(cfg, store, device, tx);
    let mut events = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(250));

    loop {
        terminal.draw(|frame| app.draw(frame))?;
        if app.should_quit() {
            break;
        }

        tokio::select! {
            maybe = events.next() => match maybe {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    app.update(Msg::Key(key));
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            },
            Some(msg) = rx.recv() => app.update(msg),
            _ = ticker.tick() => app.update(Msg::Tick),
        }
    }

    Ok(())
}
