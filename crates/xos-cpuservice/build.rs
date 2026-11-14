use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=app.rc");
    println!("cargo:rerun-if-changed=app.manifest");
    let rc = versioned_rc("app.rc", "XOS CPU Service", "XOS-CpuService.exe");
    embed_resource::compile(&rc, embed_resource::NONE).manifest_required().expect("resource compile");
}

fn versioned_rc(source: &str, description: &str, file_name: &str) -> String {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap().replace('\\', "/");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut parts: Vec<u16> = version.split(['.', '-', '+']).take(3).map(|p| p.parse().unwrap_or(0)).collect();
    parts.resize(4, 0);
    let commas = parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    let dotted = parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".");
    let base = std::fs::read_to_string(Path::new(&dir).join(source)).expect("read app.rc");
    let base = base
        .replace("\"assets/", &format!("\"{dir}/assets/"))
        .replace("\"app.manifest\"", &format!("\"{dir}/app.manifest\""));
    let block = format!(
        r#"
1 VERSIONINFO
FILEVERSION {commas}
PRODUCTVERSION {commas}
FILEOS 0x40004
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "XOS-Toolkit"
      VALUE "FileDescription", "{description}"
      VALUE "FileVersion", "{dotted}"
      VALUE "InternalName", "{file_name}"
      VALUE "OriginalFilename", "{file_name}"
      VALUE "ProductName", "XOS Toolkit"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#
    );
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("app-versioned.rc");
    std::fs::write(&out, format!("{base}\n{block}")).expect("write versioned rc");
    out.to_string_lossy().into_owned()
}
