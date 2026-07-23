fn main() {
    println!("cargo:rerun-if-changed=../../assets/legion-icon.png");
    embed_windows_icon();
}

#[cfg(target_os = "windows")]
fn embed_windows_icon() {
    use std::{env, path::PathBuf};

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    // The square app icon (purple "L" tile), the same image the Linux AppImage
    // ships — not assets/legion.png, which is the wide dashboard screenshot and
    // squashed into a lopsided taskbar icon.
    let source_png = manifest_dir.join("../../assets/legion-icon.png");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let icon_path = out_dir.join("legion.ico");

    let image = image::open(&source_png).expect("load legion-icon.png");
    let icon_image = image.thumbnail(256, 256);
    icon_image
        .save_with_format(&icon_path, image::ImageFormat::Ico)
        .expect("write legion.ico");

    let mut resource = winres::WindowsResource::new();
    resource.set_icon(icon_path.to_str().expect("icon path utf-8"));
    resource.compile().expect("embed Windows icon resource");
}

#[cfg(not(target_os = "windows"))]
fn embed_windows_icon() {}
