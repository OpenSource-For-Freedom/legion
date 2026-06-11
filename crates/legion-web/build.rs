fn main() {
    println!("cargo:rerun-if-changed=../../assets/legion.png");
    embed_windows_icon();
}

#[cfg(target_os = "windows")]
fn embed_windows_icon() {
    use std::{env, path::PathBuf};

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let source_png = manifest_dir.join("../../assets/legion.png");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let icon_path = out_dir.join("legion.ico");

    let image = image::open(&source_png).expect("load legion.png");
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
