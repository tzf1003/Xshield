//! Owns live internal TCP sockets and serializes listener changes with edge apply.
//!
//! Each accepted connection is handed to [`EdgeTransport`] (PROXY header from
//! a trusted balancer, socket metadata, TLS) in its own task before Pingora
//! sees it, so a slow or hostile handshake never blocks the accept loop.

use crate::Gateway;
use pingora::{apps::ServerApp, proxy::HttpProxy, server::ShutdownWatch};
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::Mutex, task::JoinHandle};
use xshield_gateway::edge_transport::{EdgeTransport, ListenerSetupSlots, TransportStatus};
use xshield_gateway::multi_site::{ApplyCoordinator, GatewaySnapshot, SnapshotRefusal};

pub(crate) enum ApplyError {
    StaleRevision,
    RevisionConflict,
    ListenerUnavailable,
}

pub(crate) struct ListenerSupervisor {
    coordinator: Arc<ApplyCoordinator>,
    app: Arc<HttpProxy<Gateway, ()>>,
    transport: Arc<EdgeTransport>,
    bind_ip: IpAddr,
    shutdown: ShutdownWatch,
    // The lock covers binding and the snapshot swap. An apply cannot expose
    // a route until every socket needed by that generation is bound.
    listeners: Mutex<BTreeMap<u16, JoinHandle<()>>>,
}

impl ListenerSupervisor {
    pub(crate) async fn new(
        coordinator: Arc<ApplyCoordinator>,
        app: Arc<HttpProxy<Gateway, ()>>,
        transport: Arc<EdgeTransport>,
        bind_ip: IpAddr,
        initial_addresses: &[SocketAddr],
        shutdown: ShutdownWatch,
    ) -> io::Result<Self> {
        let mut bound = Vec::with_capacity(initial_addresses.len());
        for address in initial_addresses {
            bound.push((address.port(), TcpListener::bind(address).await?));
        }
        let supervisor = Self {
            coordinator,
            app,
            transport,
            bind_ip,
            shutdown,
            listeners: Mutex::new(BTreeMap::new()),
        };
        let mut listeners = supervisor.listeners.lock().await;
        for (port, listener) in bound {
            listeners.insert(port, supervisor.spawn_listener(listener));
        }
        drop(listeners);
        Ok(supervisor)
    }

    pub(crate) async fn apply(&self, snapshot: GatewaySnapshot) -> Result<u64, ApplyError> {
        let mut listeners = self.listeners.lock().await;
        // Same question the store asks under its write lock; asking it here
        // first keeps a refused snapshot from binding any socket.
        match self.coordinator.current().check_replacement(&snapshot) {
            Ok(()) => {}
            Err(SnapshotRefusal::Stale) => return Err(ApplyError::StaleRevision),
            Err(SnapshotRefusal::Conflict) => return Err(ApplyError::RevisionConflict),
        }
        let required = snapshot.listener_ports();
        let mut newly_bound = Vec::new();
        for port in required.iter().copied() {
            if !listeners.contains_key(&port) {
                let address = SocketAddr::new(self.bind_ip, port);
                let listener = TcpListener::bind(address)
                    .await
                    .map_err(|_| ApplyError::ListenerUnavailable)?;
                newly_bound.push((port, listener));
            }
        }
        for (port, listener) in newly_bound {
            listeners.insert(port, self.spawn_listener(listener));
        }
        let Some(revision) = self.coordinator.apply_if_current_or_newer(snapshot) else {
            // The supervisor is the only production writer; this guard also
            // keeps a future competing writer from leaving extra sockets.
            for port in listeners.keys().copied().collect::<Vec<_>>() {
                if !self.coordinator.current().listener_ports().contains(&port)
                    && let Some(handle) = listeners.remove(&port)
                {
                    handle.abort();
                }
            }
            return Err(ApplyError::StaleRevision);
        };
        for port in listeners.keys().copied().collect::<Vec<_>>() {
            if !required.contains(&port)
                && let Some(handle) = listeners.remove(&port)
            {
                handle.abort();
            }
        }
        Ok(revision)
    }

    pub(crate) fn current(&self) -> Arc<GatewaySnapshot> {
        self.coordinator.current()
    }

    pub(crate) async fn listener_count(&self) -> usize {
        self.listeners.lock().await.len()
    }

    /// TLS/PROXY configuration and connection-setup failure counters.
    pub(crate) fn transport_status(&self) -> TransportStatus {
        self.transport.status()
    }

    /// Stops all data-plane listeners after a durability failure. The apply
    /// channel remains available so an operator can repair storage and retry.
    pub(crate) async fn fail_closed(&self) {
        let mut listeners = self.listeners.lock().await;
        for handle in listeners.values() {
            handle.abort();
        }
        listeners.clear();
    }

    fn spawn_listener(&self, listener: TcpListener) -> JoinHandle<()> {
        let app = Arc::clone(&self.app);
        let transport = Arc::clone(&self.transport);
        let slots = ListenerSetupSlots::new();
        let mut shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => match accepted {
                        Ok((tcp, peer)) => {
                            // Slots are reserved here, before a task exists,
                            // so a flood is shed instead of queued; a refused
                            // socket is closed when `tcp` drops.
                            if let Some(setup) = transport.admit(peer, &slots) {
                                let app = Arc::clone(&app);
                                let transport = Arc::clone(&transport);
                                let shutdown = shutdown.clone();
                                tokio::spawn(async move {
                                    let Some(stream) = transport.establish(tcp, setup).await else {
                                        return;
                                    };
                                    let mut event = Some(stream);
                                    while let Some(stream) = event {
                                        event = app.process_new(stream, &shutdown).await;
                                    }
                                });
                            }
                        }
                        Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                    }
                }
            }
        })
    }
}

impl Drop for ListenerSupervisor {
    fn drop(&mut self) {
        if let Ok(listeners) = self.listeners.try_lock() {
            for handle in listeners.values() {
                handle.abort();
            }
        }
    }
}
