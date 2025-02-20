use std::task::Poll;

use s2n_quic::provider::tls::Provider;
use s2n_quic_core::{
    application::ServerName,
    crypto::{
        tls::{Context, Endpoint, Session},
        CryptoSuite,
    },
    havoc::EncoderValue,
    transport::Error,
};
use s2n_tls_sys::{
    s2n_connection, s2n_connection_free, s2n_connection_new, s2n_connection_wipe, s2n_mode,
};

use crate::crypto::Suite;

/// TODO
#[derive(Debug)]
pub struct Server {}

impl Provider for Server {
    type Server = Self;
    type Client = Client;
    type Error = core::convert::Infallible;

    fn start_server(self) -> Result<Self::Server, Self::Error> {
        Ok(self)
    }

    fn start_client(self) -> Result<Self::Client, Self::Error> {
        unreachable!("cannot create a client from a server");
    }
}

impl Endpoint for Server {
    type Session = TlsSession;

    fn new_server_session<Params: EncoderValue>(
        &mut self,
        _transport_parameters: &Params,
    ) -> Self::Session {
        todo!()
    }

    fn new_client_session<Params: EncoderValue>(
        &mut self,
        _transport_parameters: &Params,
        _server_name: ServerName,
    ) -> Self::Session {
        unreachable!("cannot create a client session from a server config")
    }

    fn max_tag_length(&self) -> usize {
        s2n_quic_crypto::MAX_TAG_LEN
    }
}

/// TODO
#[derive(Debug)]
pub struct Client {}

impl Provider for Client {
    type Server = Server;
    type Client = Self;
    type Error = core::convert::Infallible;

    fn start_server(self) -> Result<Self::Server, Self::Error> {
        unreachable!("cannot create a server from a client");
    }

    fn start_client(self) -> Result<Self::Client, Self::Error> {
        Ok(self)
    }
}

impl Endpoint for Client {
    type Session = TlsSession;

    fn new_server_session<Params: EncoderValue>(
        &mut self,
        _transport_parameters: &Params,
    ) -> Self::Session {
        unreachable!("cannot create a server session from a client config")
    }

    fn new_client_session<Params: EncoderValue>(
        &mut self,
        _transport_parameters: &Params,
        _server_name: ServerName,
    ) -> Self::Session {
        todo!()
    }

    fn max_tag_length(&self) -> usize {
        s2n_quic_crypto::MAX_TAG_LEN
    }
}

#[derive(Debug)]
struct TlsSession {}

impl TlsSession {}

impl Session for TlsSession {
    fn poll<C: Context<Self>>(&mut self, _context: &mut C) -> Poll<Result<(), Error>> {
        todo!()
    }
}

impl CryptoSuite for TlsSession {
    type HandshakeKey = <Suite as CipherSuite>::HandshakeKey;
    type HandshakeHeaderKey = <Suite as CipherSuite>::HandshakeHeaderKey;
    type InitialKey = <Suite as CipherSuite>::InitialKey;
    type InitialHeaderKey = <Suite as CipherSuite>::InitialHeaderKey;
    type OneRttKey = <Suite as CipherSuite>::OneRttKey;
    type OneRttHeaderKey = <Suite as CipherSuite>::OneRttHeaderKey;
    type ZeroRttKey = <Suite as CipherSuite>::ZeroRttKey;
    type ZeroRttHeaderKey = <Suite as CipherSuite>::ZeroRttHeaderKey;
    type RetryKey = <Suite as CipherSuite>::RetryKey;
}

#[derive(Debug)]
struct Conn(*mut s2n_connection);

impl Conn {
    fn new(server: bool) -> Self {
        let mode = if server {
            s2n_mode::SERVER
        } else {
            s2n_mode::CLIENT
        };
        // SAFETY: FFI call, no invariants.
        let conn = unsafe { s2n_connection_new(mode) };
        Self(conn)
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: `self.0` is non-null. Otherwise, FFI call
        // with no invariants.
        unsafe {
            s2n_connection_wipe(self.0);
            s2n_connection_free(self.0);
        }
    }
}

/// # Safety
///
/// `s2n_connection` can be sent across threads.
unsafe impl Send for Conn {}
