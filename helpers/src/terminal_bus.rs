// SPDX-License-Identifier: MIT
//! The terminal manager is pinned to the initial system manager's unique owner.
use enzimos_platform::{Error, Result, files, process_identity, require};
use std::{future::Future, path::PathBuf, time::Duration};
use zbus::{
    Connection, Proxy,
    fdo::DBusProxy,
    names::{BusName, OwnedUniqueName},
    zvariant::{DynamicDeserialize, DynamicType},
};
pub const PATH: &str = "/org/freedesktop/systemd1";
pub const MANAGER: &str = "org.freedesktop.systemd1.Manager";
async fn bounded<T, F: Future<Output = zbus::Result<T>>>(future: F) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .map_err(|_| Error("terminal provider deadline; outcome may be uncertain".into()))?
        .map_err(|_| Error("terminal provider unavailable; no automatic retry".into()))
}
pub struct Manager {
    connection: Connection,
    owner: OwnedUniqueName,
    process: process_identity::Retained,
}
impl Manager {
    pub async fn new() -> Result<Self> {
        enzimos_policy::namespaces::initial()?;
        let connection = bounded(Connection::system()).await?;
        let daemon = DBusProxy::new(&connection)
            .await
            .map_err(|_| Error("system bus unavailable".into()))?;
        let name = BusName::try_from("org.freedesktop.systemd1").unwrap();
        let owner = tokio::time::timeout(Duration::from_secs(2), daemon.get_name_owner(name))
            .await
            .map_err(|_| Error("system manager owner deadline".into()))?
            .map_err(|_| Error("system manager unavailable".into()))?;
        let bus_name = BusName::from(owner.as_ref());
        let process = tokio::time::timeout(
            Duration::from_secs(2),
            daemon.get_connection_unix_process_id(bus_name.clone()),
        )
        .await
        .map_err(|_| Error("system manager PID deadline".into()))?
        .map_err(|_| Error("system manager PID unavailable".into()))?;
        let root = tokio::time::timeout(
            Duration::from_secs(2),
            daemon.get_connection_unix_user(bus_name),
        )
        .await
        .map_err(|_| Error("system manager UID deadline".into()))?
        .map_err(|_| Error("system manager UID unavailable".into()))?;
        require(
            process == 1 && root == 0,
            "initial Root system manager required",
        )?;
        let body = files::read_kernel(&PathBuf::from("/proc/1/stat"), 8192)?;
        let stat = process_identity::parse_stat(
            std::str::from_utf8(&body)
                .map_err(|_| Error("system manager identity encoding".into()))?,
            1,
        )?;
        let retained = process_identity::Retained::open(
            1,
            stat.start_ticks,
            0,
            &[PathBuf::from("/usr/lib/systemd/systemd")],
        )?;
        let manager = Self {
            connection,
            owner,
            process: retained,
        };
        manager.recheck().await?;
        Ok(manager)
    }
    pub async fn recheck(&self) -> Result<()> {
        self.process.recheck()?;
        let daemon = DBusProxy::new(&self.connection)
            .await
            .map_err(|_| Error("system bus unavailable".into()))?;
        let owner = tokio::time::timeout(
            Duration::from_secs(2),
            daemon.get_name_owner(BusName::try_from("org.freedesktop.systemd1").unwrap()),
        )
        .await
        .map_err(|_| Error("system manager owner deadline".into()))?
        .map_err(|_| Error("system manager owner lost".into()))?;
        require(
            owner == self.owner,
            "system manager owner changed; no retry",
        )
    }
    pub async fn call<B, R>(&self, path: &str, interface: &str, method: &str, body: &B) -> Result<R>
    where
        B: serde::Serialize + DynamicType,
        R: for<'d> DynamicDeserialize<'d>,
    {
        self.recheck().await?;
        let proxy = bounded(Proxy::new(
            &self.connection,
            self.owner.as_str(),
            path,
            interface,
        ))
        .await?;
        let result = bounded(proxy.call(method, body)).await?;
        self.recheck().await?;
        Ok(result)
    }
    pub async fn unit(&self) -> Result<Option<zbus::zvariant::OwnedObjectPath>> {
        self.recheck().await?;
        let proxy = bounded(Proxy::new(
            &self.connection,
            self.owner.as_str(),
            PATH,
            MANAGER,
        ))
        .await?;
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            proxy.call("GetUnit", &(crate::terminal_contract::UNIT,)),
        )
        .await
        .map_err(|_| Error("terminal lookup deadline".into()))?;
        self.recheck().await?;
        match result {
            Ok(path) => Ok(Some(path)),
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
            {
                Ok(None)
            }
            Err(_) => Err(Error("terminal lookup failed; no automatic retry".into())),
        }
    }
}
