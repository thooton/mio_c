# mio_c
C bindings for mio
```cpp
#include "mio.h"
#include <string.h>
#include <stdio.h>

const int SERVER_TOKEN = 0;
const int CLIENT_TOKEN = 1;

typedef struct {
    Mio mio;
    MioTcpServer server;
    MioTcpClient client;
} SrvData;

static void srv_callback(char* userdata, uint32_t token, uint32_t kind) {
    SrvData* srv = (SrvData*)userdata;
    uint32_t err;
    if (token == SERVER_TOKEN) {
        if (kind & MIO_CLOSED) {
            puts("mio server error");
            return;
        }
        srv->client = mio_tcp_server_accept(&srv->server, &err);
        if (err) {
            puts("can't accept client");
        } else {
            err = mio_tcp_client_register(
                &srv->mio, &srv->client,
                CLIENT_TOKEN, MIO_READABLE|MIO_WRITABLE
            );
            if (err) {
                puts("couldn't register client");
            }
        }
        err = mio_tcp_server_reregister(
            &srv->mio, &srv->server, SERVER_TOKEN, MIO_READABLE
        );
        if (err) {
            puts("couldn't reregister client");
        }
    } else if (token == CLIENT_TOKEN) {
        if (kind & MIO_CLOSED) {
            puts("mio client closed");
            return;
        }
        if (kind & MIO_WRITABLE) {
            puts("mio client writable");
            const char* welcome_msg = "Welcome to mio demo!\n";
            uint32_t amt_written = mio_tcp_client_write(
                &srv->client, welcome_msg,
                strlen(welcome_msg), &err
            );
            if (err) {
                puts("couldn't send msg to client");
                return;
            } else {
                printf("wrote (%d/%d) of welcome msg\n", amt_written, (int)strlen(welcome_msg));
            }
        } else {
            char buf[1024];
            uint32_t amt_read = mio_tcp_client_read(
                &srv->client, buf, sizeof(buf), &err
            );
            if (err) {
                puts("couldn't read from client");
                return;
            } else if (amt_read == 0) {
                puts("amt_read is 0");
                return;
            }
            uint32_t amt_written = mio_tcp_client_write(
                &srv->client, buf, amt_read, &err
            );
            if (err) {
                puts("couldn't write to client");
                return;
            }
            printf("wrote (%d/%d) of received bytes\n", amt_written, amt_read);
        }
        err = mio_tcp_client_reregister(&srv->mio, &srv->client, CLIENT_TOKEN, MIO_READABLE);
        if (err) {
            puts("couldn't reregister client");
            return;
        }
    }
}

int main(void) {
    uint32_t err = 0;
    SrvData srv;
    srv.mio = mio_new(100, &err);
    if (err) {
        puts("can't make mio");
        return 1;
    }
    const char* listen_addr = "127.0.0.1:56643";
    MioSockAddr addr = mio_sock_addr_from(listen_addr, strlen(listen_addr), &err);
    if (err) {
        puts("can't parse sock addr");
        return 1;
    }
    srv.server = mio_tcp_server_new(addr, &err);
    if (err) {
        puts("can't make server");
        return 1;
    }
    err = mio_tcp_server_register(&srv.mio, &srv.server, SERVER_TOKEN, MIO_READABLE);
    if (err) {
        puts("can't register mio tcp server");
        return 1;
    }
    printf("listening @ %s\n", listen_addr);
    while (1) {
        puts("polling");
        err = mio_poll(&srv.mio, &srv_callback, (char*)&srv);
        if (err) {
            puts("can't mio poll");
            return 1;
        }
    }
}
```