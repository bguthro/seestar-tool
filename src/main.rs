mod apk;
mod apkpure;
mod firmware;
mod gui;
mod pem;
mod runner;
mod task;
mod tui;

fn app_icon() -> egui::IconData {
    let bytes = include_bytes!("../assets/icons/hicolor/256x256/seestar-tool.png");
    let image = image::load_from_memory(bytes)
        .expect("bundled icon is valid PNG")
        .into_rgba8();
    let (width, height) = image.dimensions();
    egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    }
}

fn no_display(e: &str) -> bool {
    e.contains("WAYLAND_DISPLAY")
        || e.contains("WAYLAND_SOCKET")
        || e.contains("DISPLAY")
        || e.contains("os error")
        || e.contains("EventLoopError")
        || e.contains("NoAvailableAdapter")
}

fn main() -> anyhow::Result<()> {
    let use_tui = std::env::args().any(|a| a == "--tui");

    if use_tui {
        let rt = std::sync::Arc::new(tokio::runtime::Runtime::new()?);
        return tui::run(rt);
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Seestar Tool")
            .with_inner_size([760.0, 620.0])
            .with_min_inner_size([520.0, 440.0])
            .with_icon(app_icon()),
        ..Default::default()
    };

    let result = eframe::run_native(
        "Seestar Tool",
        options,
        Box::new(|cc| Ok(Box::new(gui::SeestarApp::new(cc)))),
    );

    if let Err(e) = result {
        let msg = e.to_string();
        if no_display(&msg) {
            eprintln!("No display available, falling back to TUI mode.");
            let rt = std::sync::Arc::new(tokio::runtime::Runtime::new()?);
            return tui::run(rt);
        }
        return Err(anyhow::anyhow!("{e}"));
    }

    Ok(())
}
