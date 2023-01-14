use mio::{Events, Poll, net::{TcpListener, TcpStream, UdpSocket}};
use std::{env, fs::File, io::Write};

#[repr(C)]
struct Mio {
    poll: Poll,
    events: Events
}

#[repr(C)]
struct MioTcpServer {
    inner: TcpListener
}

#[repr(C)]
struct MioTcpClient {
    inner: TcpStream
}

#[repr(C)]
pub struct MioUdpSocket {
    inner: UdpSocket,
}

fn opaqueFor<T>() -> String {
    let sz = std::mem::size_of::<T>();
    let align = std::mem::align_of::<T>();
    if align == 8 {
        return format!("uint64_t opaque[{}];\n", sz/8);
    } else if align == 4 {
        return format!("uint32_t opaque[{}];\n", sz/4);
    } else {
        panic!("???");
    }
}

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut bindings = Vec::new();
    cbindgen::Builder::new()
      .with_crate(crate_dir)
      .with_language(cbindgen::Language::C)
      .with_no_includes()
      .with_sys_include("stdint.h")
      .generate()
      .expect("Unable to generate bindings")
      .write(&mut bindings);
    let mut mio = String::from_utf8(bindings).unwrap();
    mio = mio.replace("Poll poll;", "");
    mio = mio.replace("Events events;", &opaqueFor::<Mio>());
    mio = mio.replace("TcpListener inner;", &opaqueFor::<MioTcpServer>());
    mio = mio.replace("TcpStream inner;", &opaqueFor::<MioTcpClient>());
    mio = mio.replace("UdpSocket inner;", &opaqueFor::<MioUdpSocket>());
    mio = mio.replace("uint8_t *", "char *");
    mio = mio.replace("uint8_t*", "char*");
    File::create("mio.h")
        .unwrap()
        .write_all(mio.as_bytes())
        .unwrap();
}