mod apk;
mod apkpure;
mod app;
mod firmware;
mod pem;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Seestar Tool")
            .with_inner_size([760.0, 620.0])
            .with_min_inner_size([520.0, 440.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Seestar Tool",
        options,
        Box::new(|cc| Ok(Box::new(app::SeestarApp::new(cc)))),
    )
}
