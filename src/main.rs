mod apk;
mod apkpure;
mod app;
mod firmware;
mod pem;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Seestar Tool")
            .with_inner_size([720.0, 560.0])
            .with_min_inner_size([480.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Seestar Tool",
        options,
        Box::new(|cc| Ok(Box::new(app::SeestarApp::new(cc)))),
    )
}
