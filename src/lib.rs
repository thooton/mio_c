use mio::{net::TcpListener, net::{TcpStream, UdpSocket}, Events, Interest, Poll, Token};
use std::{
    io::{ErrorKind, Read, Write},
    net::{AddrParseError, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr},
};


#[repr(C)]
pub struct Mio {
    poll: Poll,
    events: Events
}



#[no_mangle] pub extern "C" fn mio_new(evt_bufsz: u32, err: *mut u32) -> Mio {
    let poll_maybe = Poll::new();
    if poll_maybe.is_err() {
        unsafe {
            *err = 1;
            return std::mem::zeroed();
        }
    }
    unsafe { *err = 0; }
    return Mio{
        poll: poll_maybe.unwrap(),
        events: Events::with_capacity(evt_bufsz as usize)
    };
}


#[repr(C)]
#[derive(Clone, Copy)]
pub struct MioV4 {
    ip: [u8; 4],
    port: u16
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MioV6 {
    flowinfo: u32,
    scope_id: u32,
    ip: [u16; 8],
    port: u16
}

#[repr(C)]
pub union MioSockAddrInner {
    v4: MioV4,
    v6: MioV6
}

#[repr(C)]
pub struct MioSockAddr {
    inner: MioSockAddrInner,
    is_v4: u8
}


#[inline(always)]
fn toRustAddr(sock_addr: MioSockAddr) -> SocketAddr {
    if sock_addr.is_v4 != 0 {
        unsafe {
            return SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(
                    sock_addr.inner.v4.ip
                ),
                sock_addr.inner.v4.port
            ));
        }
    } else {
        unsafe {
            return SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(
                    sock_addr.inner.v6.ip
                ),
                sock_addr.inner.v6.port,
                sock_addr.inner.v6.flowinfo,
                sock_addr.inner.v6.scope_id
            ));
        }
    }
}
#[inline(always)]
fn toCAddr(sock_addr: SocketAddr) -> MioSockAddr {
    match sock_addr {
        SocketAddr::V4(the_v4) => {
            return MioSockAddr{
                inner: MioSockAddrInner{
                    v4: MioV4{
                        ip: the_v4.ip().octets(),
                        port: the_v4.port()
                    }
                },
                is_v4: 1
            };
        },
        SocketAddr::V6(the_v6) => {
            return MioSockAddr{
                inner: MioSockAddrInner{
                    v6: MioV6{
                        flowinfo: the_v6.flowinfo(),
                        scope_id: the_v6.scope_id(),
                        ip: the_v6.ip().segments(),
                        port: the_v6.port()
                    }
                },
                is_v4: 0
            }
        }
    }
}
#[no_mangle] pub extern "C" fn mio_sock_addr_from(addr: *const u8, addr_len: u32, err: *mut u32) -> MioSockAddr {
    let addr_slice = unsafe {
        core::slice::from_raw_parts(addr, addr_len as usize)
    };
    let addr_str_maybe = unsafe {
        core::str::from_utf8(addr_slice)
    };
    if addr_str_maybe.is_err() {
        unsafe {
            *err = 1;
            return std::mem::zeroed();
        }
    }
    let sock_addr_maybe: Result<SocketAddr, AddrParseError> = addr_str_maybe.unwrap().parse();
    if sock_addr_maybe.is_err() {
        unsafe {
            *err = 1;
            return std::mem::zeroed();
        }
    }
    unsafe { *err = 0; }
    return toCAddr(sock_addr_maybe.unwrap());
}


#[repr(C)]
pub struct MioTcpServer {
    inner: TcpListener
}



#[no_mangle] pub extern "C" fn mio_tcp_server_new(
    sock_addr: MioSockAddr, err: *mut u32
) -> MioTcpServer {
    let server_maybe = TcpListener::bind(toRustAddr(sock_addr));
    if server_maybe.is_err() {
        unsafe {
            *err = 1;
            return std::mem::zeroed();
        }
    }
    unsafe { *err = 0; }
    return MioTcpServer{
        inner: server_maybe.unwrap()
    };
}
pub const MIO_READABLE: u32 = 1;
pub const MIO_WRITABLE: u32 = 2;
pub const MIO_CLOSED: u32 = 4;
#[inline(always)]
fn parseInterests(interests: u32) -> Interest {
    let mut int = Interest::READABLE;
    if (interests & MIO_WRITABLE) != 0 {
        int |= Interest::WRITABLE;
        if (interests & MIO_READABLE) == 0 {
            int |= Interest::READABLE;
        }
    }
    return int;
}

        
            #[no_mangle] pub extern "C" fn mio_tcp_server_register(
                mio: *mut Mio, server: *mut MioTcpServer,
                token: u32, interests: u32
            ) -> u32 {
                let res = unsafe {
                    (*mio).poll.registry().register(
                        &mut ((*server).inner), Token(token as usize),
                        parseInterests(interests)
                    )
                };
                if res.is_err() {
                    return 1;
                }
                return 0;
            }
        
        
            #[no_mangle] pub extern "C" fn mio_tcp_server_reregister(
                mio: *mut Mio, server: *mut MioTcpServer,
                token: u32, interests: u32
            ) -> u32 {
                let res = unsafe {
                    (*mio).poll.registry().reregister(
                        &mut ((*server).inner), Token(token as usize),
                        parseInterests(interests)
                    )
                };
                if res.is_err() {
                    return 1;
                }
                return 0;
            }
        
        pub extern "C" fn mio_tcp_server_deregister(
            mio: *mut Mio, server: *mut MioTcpServer
        ) -> u32 {
            let res = unsafe {
                (*mio).poll.registry().deregister(
                    &mut ((*server).inner)
                )
            };
            if res.is_err() {
                return 1;
            }
            return 0;
        }
    



#[repr(C)]
pub struct MioTcpClient {
    inner: TcpStream
}



#[no_mangle] pub extern "C" fn mio_tcp_client_new(
    socket_addr: MioSockAddr, err: *mut u32
) -> MioTcpClient {
    let client_maybe = TcpStream::connect(toRustAddr(socket_addr));
    if client_maybe.is_err() {
        unsafe {
            *err = 1;
            return std::mem::zeroed();
        }
    }
    unsafe { *err = 0; }
    return MioTcpClient{
        inner: client_maybe.unwrap()
    };
}

        
            #[no_mangle] pub extern "C" fn mio_tcp_client_register(
                mio: *mut Mio, client: *mut MioTcpClient,
                token: u32, interests: u32
            ) -> u32 {
                let res = unsafe {
                    (*mio).poll.registry().register(
                        &mut ((*client).inner), Token(token as usize),
                        parseInterests(interests)
                    )
                };
                if res.is_err() {
                    return 1;
                }
                return 0;
            }
        
        
            #[no_mangle] pub extern "C" fn mio_tcp_client_reregister(
                mio: *mut Mio, client: *mut MioTcpClient,
                token: u32, interests: u32
            ) -> u32 {
                let res = unsafe {
                    (*mio).poll.registry().reregister(
                        &mut ((*client).inner), Token(token as usize),
                        parseInterests(interests)
                    )
                };
                if res.is_err() {
                    return 1;
                }
                return 0;
            }
        
        pub extern "C" fn mio_tcp_client_deregister(
            mio: *mut Mio, client: *mut MioTcpClient
        ) -> u32 {
            let res = unsafe {
                (*mio).poll.registry().deregister(
                    &mut ((*client).inner)
                )
            };
            if res.is_err() {
                return 1;
            }
            return 0;
        }
    

#[no_mangle] pub extern "C" fn mio_tcp_server_accept(
    server: *const MioTcpServer, err: *mut u32
) -> MioTcpClient {
    let res = unsafe { (*server).inner.accept() };
    if res.is_err() {
        unsafe {
            *err = 1;
            return std::mem::zeroed();
        }
    }
    unsafe { *err = 0; }
    return MioTcpClient{
        inner: res.unwrap().0
    }
}

        #[no_mangle]
        pub extern "C" fn mio_tcp_server_set_ttl(
            server: *const MioTcpServer, ttl: u32
        ) -> u32 {
            let res = unsafe { (*server).inner.set_ttl(ttl) };
            if res.is_err() {
                return 1;
            }
            return 0;
        }

        #[no_mangle]
        pub extern "C" fn mio_tcp_server_ttl(
            server: *const MioTcpServer, err: *mut u32
        ) -> u32 {
            let res = unsafe { (*server).inner.ttl() };
            if res.is_err() {
                unsafe { *err = 1; }
                return 0;
            }
            unsafe { *err = 0; }
            return res.unwrap();
        }
    

        #[no_mangle]
        pub extern "C" fn mio_tcp_client_shutdown_read(
            client: *const MioTcpClient
        ) -> u32 {
            let res = unsafe { (*client).inner.shutdown(Shutdown::Read) };
            if res.is_err() {
                return 1;
            }
            return 0;
        }
    

        #[no_mangle]
        pub extern "C" fn mio_tcp_client_shutdown_write(
            client: *const MioTcpClient
        ) -> u32 {
            let res = unsafe { (*client).inner.shutdown(Shutdown::Write) };
            if res.is_err() {
                return 1;
            }
            return 0;
        }
    

        #[no_mangle]
        pub extern "C" fn mio_tcp_client_shutdown_both(
            client: *const MioTcpClient
        ) -> u32 {
            let res = unsafe { (*client).inner.shutdown(Shutdown::Both) };
            if res.is_err() {
                return 1;
            }
            return 0;
        }
    

#[no_mangle] pub extern "C" fn mio_tcp_client_set_nodelay(
    client: *const MioTcpClient, nodelay: u32
) -> u32 {
    let res = unsafe { (*client).inner.set_nodelay(nodelay != 0) };
    if res.is_err() {
        return 1;
    }
    return 0;
}
#[no_mangle] pub extern "C" fn mio_tcp_client_get_nodelay(
    client: *const MioTcpClient, err: *mut u32
) -> u32 {
    let res = unsafe { (*client).inner.nodelay() };
    if res.is_err() {
        unsafe { *err = 1; }
        return 0;
    }
    unsafe { *err = 0; }
    let nodelay = res.unwrap();
    if nodelay {
        return 1;
    } else {
        return 0;
    }
}

        #[no_mangle]
        pub extern "C" fn mio_tcp_client_set_ttl(
            client: *const MioTcpClient, ttl: u32
        ) -> u32 {
            let res = unsafe { (*client).inner.set_ttl(ttl) };
            if res.is_err() {
                return 1;
            }
            return 0;
        }

        #[no_mangle]
        pub extern "C" fn mio_tcp_client_ttl(
            client: *const MioTcpClient, err: *mut u32
        ) -> u32 {
            let res = unsafe { (*client).inner.ttl() };
            if res.is_err() {
                unsafe { *err = 1; }
                return 0;
            }
            unsafe { *err = 0; }
            return res.unwrap();
        }
    

        #[no_mangle]
        pub extern "C" fn mio_tcp_client_peek(
            client: *const MioTcpClient, buf: *mut u8, buf_len: u32, err: *mut u32
        ) -> u32 {
            let client_ref = unsafe { & *client };
            let sl = unsafe {
                core::slice::from_raw_parts_mut(buf, buf_len as usize)
            };
            loop {
                let res = client_ref.inner.peek(sl);
                match res {
                    Ok(amt) => {
                        unsafe { *err = 0; }
                        return amt as u32;
                    },
                    Err(e) => {
                        if e.kind() != ErrorKind::Interrupted {
                            unsafe { *err = 1; }
                            return 0;
                        }
                    }
                }
            }
        }
    

        #[no_mangle]
        pub extern "C" fn mio_tcp_client_read(
            client: *mut MioTcpClient, buf: *mut u8, buf_len: u32, err: *mut u32
        ) -> u32 {
            let client_ref = unsafe { &mut *client };
            let sl = unsafe {
                core::slice::from_raw_parts_mut(buf, buf_len as usize)
            };
            loop {
                let res = client_ref.inner.read(sl);
                match res {
                    Ok(amt) => {
                        unsafe { *err = 0; }
                        return amt as u32;
                    },
                    Err(e) => {
                        if e.kind() != ErrorKind::Interrupted {
                            unsafe { *err = 1; }
                            return 0;
                        }
                    }
                }
            }
        }
    

        #[no_mangle]
        pub extern "C" fn mio_tcp_client_write(
            client: *mut MioTcpClient, buf: *const u8, buf_len: u32, err: *mut u32
        ) -> u32 {
            let client_ref = unsafe { &mut *client };
            let sl = unsafe {
                core::slice::from_raw_parts(buf, buf_len as usize)
            };
            loop {
                let res = client_ref.inner.write(sl);
                match res {
                    Ok(amt) => {
                        unsafe { *err = 0; }
                        return amt as u32;
                    },
                    Err(e) => {
                        if e.kind() != ErrorKind::Interrupted {
                            unsafe { *err = 1; }
                            return 0;
                        }
                    }
                }
            }
        }
    
/*
${fn} mio_tcp_client_read_exact(
    client: *mut MioTcpClient, dst: *mut u8, dst_len: u32
) -> u32 {
    let client_ref = unsafe { &mut *client };
    let dstsl = unsafe { 
        core::slice::from_raw_parts_mut(dst, dst_len as usize)
    };
    let res = client_ref.inner.read_exact(dstsl);
    if res.is_err() {
        return 1;
    }
    return 0;
}

${fn} mio_tcp_client_write_all(
    client: *mut MioTcpClient, src: *const u8, src_len: u32
) -> u32 {
    let client_ref = unsafe { &mut *client };
    let sl = unsafe { 
        core::slice::from_raw_parts(src, src_len as usize)
    };
    let res = client_ref.inner.write_all(sl);
    if res.is_err() {
        return 1;
    }
    return 0;
}*/

#[no_mangle] pub extern "C" fn mio_tcp_client_flush(
    client: *mut MioTcpClient
) -> u32 {
    let res = unsafe { (*client).inner.flush() };
    if res.is_err() {
        return 1;
    }
    return 0;
}

        #[no_mangle] pub extern "C" fn mio_tcp_client_local_addr(
            client: *mut MioTcpClient,
            err: *mut u32
        ) -> MioSockAddr {
            let res = unsafe { (*client).inner.local_addr() };
            if res.is_err() {
                unsafe {
                    *err = 1;
                    return std::mem::zeroed();
                }
            }
            unsafe { *err = 0; }
            return toCAddr(res.unwrap());
        }
    

        #[no_mangle] pub extern "C" fn mio_tcp_client_peer_addr(
            client: *mut MioTcpClient,
            err: *mut u32
        ) -> MioSockAddr {
            let res = unsafe { (*client).inner.peer_addr() };
            if res.is_err() {
                unsafe {
                    *err = 1;
                    return std::mem::zeroed();
                }
            }
            unsafe { *err = 0; }
            return toCAddr(res.unwrap());
        }
    

        #[no_mangle] pub extern "C" fn mio_tcp_server_local_addr(
            server: *mut MioTcpServer,
            err: *mut u32
        ) -> MioSockAddr {
            let res = unsafe { (*server).inner.local_addr() };
            if res.is_err() {
                unsafe {
                    *err = 1;
                    return std::mem::zeroed();
                }
            }
            unsafe { *err = 0; }
            return toCAddr(res.unwrap());
        }
    



#[repr(C)]
pub struct MioUdpSocket {
    inner: UdpSocket
}



#[no_mangle] pub extern "C" fn mio_udp_socket_new(
    sock_addr: MioSockAddr,
    err: *mut u32
) -> MioUdpSocket {
    let sock_maybe = UdpSocket::bind(toRustAddr(sock_addr));
    if sock_maybe.is_err() {
        unsafe {
            *err = 1;
            return std::mem::zeroed();
        }
    }
    unsafe { *err = 0; }
    return MioUdpSocket{
        inner: sock_maybe.unwrap()
    };
}
#[no_mangle] pub extern "C" fn mio_udp_socket_connect(
    socket: *const MioUdpSocket,
    sock_addr: MioSockAddr
) -> u32 {
    let res = unsafe { (*socket).inner.connect(toRustAddr(sock_addr)) };
    if res.is_err() {
        return 1;
    }
    return 0;
}

        #[no_mangle] pub extern "C" fn mio_udp_socket_local_addr(
            socket: *mut MioUdpSocket,
            err: *mut u32
        ) -> MioSockAddr {
            let res = unsafe { (*socket).inner.local_addr() };
            if res.is_err() {
                unsafe {
                    *err = 1;
                    return std::mem::zeroed();
                }
            }
            unsafe { *err = 0; }
            return toCAddr(res.unwrap());
        }
    

        #[no_mangle] pub extern "C" fn mio_udp_socket_peer_addr(
            socket: *mut MioUdpSocket,
            err: *mut u32
        ) -> MioSockAddr {
            let res = unsafe { (*socket).inner.peer_addr() };
            if res.is_err() {
                unsafe {
                    *err = 1;
                    return std::mem::zeroed();
                }
            }
            unsafe { *err = 0; }
            return toCAddr(res.unwrap());
        }
    

        #[no_mangle]
        pub extern "C" fn mio_udp_socket_set_ttl(
            socket: *const MioUdpSocket, ttl: u32
        ) -> u32 {
            let res = unsafe { (*socket).inner.set_ttl(ttl) };
            if res.is_err() {
                return 1;
            }
            return 0;
        }

        #[no_mangle]
        pub extern "C" fn mio_udp_socket_ttl(
            socket: *const MioUdpSocket, err: *mut u32
        ) -> u32 {
            let res = unsafe { (*socket).inner.ttl() };
            if res.is_err() {
                unsafe { *err = 1; }
                return 0;
            }
            unsafe { *err = 0; }
            return res.unwrap();
        }
    


        #[no_mangle]
        pub extern "C" fn mio_udp_socket_peek(
            socket: *const MioUdpSocket, buf: *mut u8, buf_len: u32, err: *mut u32
        ) -> u32 {
            let socket_ref = unsafe { & *socket };
            let sl = unsafe {
                core::slice::from_raw_parts_mut(buf, buf_len as usize)
            };
            loop {
                let res = socket_ref.inner.peek(sl);
                match res {
                    Ok(amt) => {
                        unsafe { *err = 0; }
                        return amt as u32;
                    },
                    Err(e) => {
                        if e.kind() != ErrorKind::Interrupted {
                            unsafe { *err = 1; }
                            return 0;
                        }
                    }
                }
            }
        }
    

        #[no_mangle]
        pub extern "C" fn mio_udp_socket_recv(
            socket: *mut MioUdpSocket, buf: *mut u8, buf_len: u32, err: *mut u32
        ) -> u32 {
            let socket_ref = unsafe { &mut *socket };
            let sl = unsafe {
                core::slice::from_raw_parts_mut(buf, buf_len as usize)
            };
            loop {
                let res = socket_ref.inner.recv(sl);
                match res {
                    Ok(amt) => {
                        unsafe { *err = 0; }
                        return amt as u32;
                    },
                    Err(e) => {
                        if e.kind() != ErrorKind::Interrupted {
                            unsafe { *err = 1; }
                            return 0;
                        }
                    }
                }
            }
        }
    

        #[no_mangle]
        pub extern "C" fn mio_udp_socket_send(
            socket: *mut MioUdpSocket, buf: *const u8, buf_len: u32, err: *mut u32
        ) -> u32 {
            let socket_ref = unsafe { &mut *socket };
            let sl = unsafe {
                core::slice::from_raw_parts(buf, buf_len as usize)
            };
            loop {
                let res = socket_ref.inner.send(sl);
                match res {
                    Ok(amt) => {
                        unsafe { *err = 0; }
                        return amt as u32;
                    },
                    Err(e) => {
                        if e.kind() != ErrorKind::Interrupted {
                            unsafe { *err = 1; }
                            return 0;
                        }
                    }
                }
            }
        }
    


        #[no_mangle] pub extern "C" fn mio_udp_socket_recv_from(
            socket: *const MioUdpSocket,
            dst: *mut u8,
            dst_len: u32,
            amt: *mut u32,
            err: *mut u32
        ) -> MioSockAddr {
            let sl = unsafe {
                core::slice::from_raw_parts_mut(dst, dst_len as usize)
            };
            loop {
                let res = unsafe { (*socket).inner.recv_from(sl) };
                match res {
                    Ok((amount, addr)) => {
                        unsafe {
                            *err = 0;
                            *amt = amount as u32;
                        }
                        return toCAddr(addr);
                    },
                    Err(e) => {
                        if e.kind() != ErrorKind::Interrupted {
                            unsafe {
                                *err = 1;
                                return std::mem::zeroed();
                            }
                        }
                    }
                }
            }
        }
    

        #[no_mangle] pub extern "C" fn mio_udp_socket_peek_from(
            socket: *const MioUdpSocket,
            dst: *mut u8,
            dst_len: u32,
            amt: *mut u32,
            err: *mut u32
        ) -> MioSockAddr {
            let sl = unsafe {
                core::slice::from_raw_parts_mut(dst, dst_len as usize)
            };
            loop {
                let res = unsafe { (*socket).inner.peek_from(sl) };
                match res {
                    Ok((amount, addr)) => {
                        unsafe {
                            *err = 0;
                            *amt = amount as u32;
                        }
                        return toCAddr(addr);
                    },
                    Err(e) => {
                        if e.kind() != ErrorKind::Interrupted {
                            unsafe {
                                *err = 1;
                                return std::mem::zeroed();
                            }
                        }
                    }
                }
            }
        }
    


        
            #[no_mangle] pub extern "C" fn mio_udp_socket_register(
                mio: *mut Mio, socket: *mut MioUdpSocket,
                token: u32, interests: u32
            ) -> u32 {
                let res = unsafe {
                    (*mio).poll.registry().register(
                        &mut ((*socket).inner), Token(token as usize),
                        parseInterests(interests)
                    )
                };
                if res.is_err() {
                    return 1;
                }
                return 0;
            }
        
        
            #[no_mangle] pub extern "C" fn mio_udp_socket_reregister(
                mio: *mut Mio, socket: *mut MioUdpSocket,
                token: u32, interests: u32
            ) -> u32 {
                let res = unsafe {
                    (*mio).poll.registry().reregister(
                        &mut ((*socket).inner), Token(token as usize),
                        parseInterests(interests)
                    )
                };
                if res.is_err() {
                    return 1;
                }
                return 0;
            }
        
        pub extern "C" fn mio_udp_socket_deregister(
            mio: *mut Mio, socket: *mut MioUdpSocket
        ) -> u32 {
            let res = unsafe {
                (*mio).poll.registry().deregister(
                    &mut ((*socket).inner)
                )
            };
            if res.is_err() {
                return 1;
            }
            return 0;
        }
    

#[no_mangle] pub extern "C" fn mio_udp_socket_send_to(
    socket: *const MioUdpSocket,
    src: *const u8,
    src_len: u32,
    target: MioSockAddr,
    err: *mut u32
) -> u32 {
    let sl = unsafe {
        core::slice::from_raw_parts(src, src_len as usize)
    };
    let addr = toRustAddr(target);
    loop {
        let res = unsafe { (*socket).inner.send_to(sl, addr) };
        match res {
            Ok(amt) => {
                unsafe { *err = 0; }
                return amt as u32;
            },
            Err(e) => {
                if e.kind() != ErrorKind::Interrupted {
                    unsafe {
                        *err = 1;
                        return std::mem::zeroed();
                    }
                }
            }
        }
    }
}
#[no_mangle] pub extern "C" fn mio_poll(
    mio: *mut Mio, 
    callback: unsafe extern "C" fn(*mut u8, u32, u32),
    userdata: *mut u8
) -> u32 {
    let mio_ref = unsafe { &mut *mio };
    loop {
        match mio_ref.poll.poll(&mut mio_ref.events, None) {
            Err(e) => {
                if e.kind() != ErrorKind::Interrupted {
                    return 1;
                }
            },
            Ok(_) => break
        };
    }
    for event in mio_ref.events.iter() {
        let tok = event.token().0 as u32;
        let mut flags: u32;
        if event.is_error() || event.is_read_closed() {
            flags = MIO_CLOSED;
        } else {
            flags = 0;
            if event.is_readable() {
                flags |= MIO_READABLE;
            }
            if event.is_writable() {
                flags |= MIO_WRITABLE;
            }
        }
        unsafe { callback(userdata, tok, flags); }
    }
    return 0;
}

