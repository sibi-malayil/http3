//! QUIC connection migration support per RFC 9000 Section 9
//!
//! Implements path validation and connection migration for QUIC connections,
//! allowing connections to survive network changes.

use crate::{
    error::{Error, Result},
    whathappened::Level,
    protocol_event,
};
use bytes::{Bytes, BytesMut};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
    collections::HashMap,
};
use tokio::sync::Mutex;
use std::sync::Arc;

/// Path state for connection migration
#[derive(Debug, Clone, PartialEq)]
pub enum PathState {
    /// Path is being validated
    Validating {
        /// Challenge data sent
        challenge_sent: Vec<u8>,
        /// Time when validation started
        started_at: Instant,
        /// Number of validation attempts
        attempts: u32,
    },
    /// Path has been validated and is active
    Active {
        /// Time when path was validated
        validated_at: Instant,
        /// RTT estimate for this path
        rtt: Duration,
    },
    /// Path validation failed
    Failed {
        /// Reason for failure
        reason: String,
        /// Time when validation failed
        failed_at: Instant,
    },
}

/// Path information for connection migration
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Local address
    pub local_addr: SocketAddr,
    /// Remote address
    pub remote_addr: SocketAddr,
    /// Current state of the path
    pub state: PathState,
    /// Packet number used for this path
    pub path_id: u64,
    /// Last activity on this path
    pub last_activity: Instant,
    /// Maximum packet size for this path
    pub max_packet_size: usize,
}

/// Connection migration manager
pub struct MigrationManager {
    /// Active paths (path_id -> PathInfo)
    paths: Arc<Mutex<HashMap<u64, PathInfo>>>,
    /// Current active path ID
    active_path_id: Arc<Mutex<u64>>,
    /// Next path ID to assign
    next_path_id: Arc<Mutex<u64>>,
    /// Migration configuration
    config: MigrationConfig,
}

/// Configuration for connection migration
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Maximum number of paths to maintain
    pub max_paths: usize,
    /// Path validation timeout
    pub validation_timeout: Duration,
    /// Maximum validation attempts
    pub max_validation_attempts: u32,
    /// Enable migration on network change
    pub enable_auto_migration: bool,
    /// Probe timeout for path validation
    pub probe_timeout: Duration,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            max_paths: 4,
            validation_timeout: Duration::from_secs(3),
            max_validation_attempts: 3,
            enable_auto_migration: true,
            probe_timeout: Duration::from_millis(100),
        }
    }
}

impl MigrationManager {
    /// Create a new migration manager
    pub fn new(config: MigrationConfig) -> Self {
        Self {
            paths: Arc::new(Mutex::new(HashMap::new())),
            active_path_id: Arc::new(Mutex::new(0)),
            next_path_id: Arc::new(Mutex::new(1)),
            config,
        }
    }

    /// Initialize with the primary path
    pub async fn init_primary_path(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<u64> {
        let path_info = PathInfo {
            local_addr,
            remote_addr,
            state: PathState::Active {
                validated_at: Instant::now(),
                rtt: Duration::from_millis(100), // Initial estimate
            },
            path_id: 0,
            last_activity: Instant::now(),
            max_packet_size: 1200, // Conservative initial value
        };

        let mut paths = self.paths.lock().await;
        paths.insert(0, path_info);

        protocol_event!(
            Level::Info,
            "Primary path initialized";
            "local_addr" => format!("{}", local_addr),
            "remote_addr" => format!("{}", remote_addr),
            "path_id" => 0
        );

        Ok(0)
    }

    /// Start path validation for a new path
    pub async fn start_path_validation(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<(u64, Vec<u8>)> {
        let mut paths = self.paths.lock().await;
        
        // Check if we already have this path
        for (_, path) in paths.iter() {
            if path.local_addr == local_addr && path.remote_addr == remote_addr {
                return Err(Error::Internal("Path already exists".to_string()));
            }
        }

        // Check path limit
        if paths.len() >= self.config.max_paths {
            return Err(Error::Internal("Maximum paths reached".to_string()));
        }

        let mut next_id = self.next_path_id.lock().await;
        let path_id = *next_id;
        *next_id += 1;

        // Generate challenge data
        let mut challenge = vec![0u8; 8];
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        rng.fill(&mut challenge).map_err(|_| Error::Internal("RNG failure".to_string()))?;

        let path_info = PathInfo {
            local_addr,
            remote_addr,
            state: PathState::Validating {
                challenge_sent: challenge.clone(),
                started_at: Instant::now(),
                attempts: 1,
            },
            path_id,
            last_activity: Instant::now(),
            max_packet_size: 1200,
        };

        paths.insert(path_id, path_info);

        protocol_event!(
            Level::Info,
            "Path validation started";
            "local_addr" => format!("{}", local_addr),
            "remote_addr" => format!("{}", remote_addr),
            "path_id" => path_id
        );

        Ok((path_id, challenge))
    }

    /// Handle PATH_CHALLENGE frame
    pub async fn handle_path_challenge(
        &self,
        data: &[u8],
        source_addr: SocketAddr,
    ) -> Result<Vec<u8>> {
        if data.len() != 8 {
            return Err(Error::ProtocolViolation("Invalid PATH_CHALLENGE data".to_string()));
        }

        protocol_event!(
            Level::Debug,
            "PATH_CHALLENGE received";
            "source_addr" => format!("{}", source_addr),
            "data_len" => data.len()
        );

        // Return the same data in PATH_RESPONSE
        Ok(data.to_vec())
    }

    /// Handle PATH_RESPONSE frame
    pub async fn handle_path_response(
        &self,
        data: &[u8],
        source_addr: SocketAddr,
    ) -> Result<Option<u64>> {
        if data.len() != 8 {
            return Err(Error::ProtocolViolation("Invalid PATH_RESPONSE data".to_string()));
        }

        let mut paths = self.paths.lock().await;
        
        // Find the path being validated
        for (path_id, path_info) in paths.iter_mut() {
            if path_info.remote_addr == source_addr {
                if let PathState::Validating { challenge_sent, started_at, .. } = &path_info.state {
                    if challenge_sent == data {
                        // Path validated successfully
                        let rtt = started_at.elapsed();
                        path_info.state = PathState::Active {
                            validated_at: Instant::now(),
                            rtt,
                        };
                        path_info.last_activity = Instant::now();

                        protocol_event!(
                            Level::Info,
                            "Path validated";
                            "path_id" => path_id,
                            "remote_addr" => format!("{}", source_addr),
                            "rtt_ms" => rtt.as_millis()
                        );

                        return Ok(Some(*path_id));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Migrate to a new path
    pub async fn migrate_to_path(&self, path_id: u64) -> Result<()> {
        let paths = self.paths.lock().await;
        
        let path = paths.get(&path_id)
            .ok_or_else(|| Error::Internal("Path not found".to_string()))?;

        // Check if path is validated
        match &path.state {
            PathState::Active { .. } => {
                let mut active_id = self.active_path_id.lock().await;
                let old_path_id = *active_id;
                *active_id = path_id;

                protocol_event!(
                    Level::Info,
                    "Connection migrated";
                    "old_path_id" => old_path_id,
                    "new_path_id" => path_id,
                    "remote_addr" => format!("{}", path.remote_addr)
                );

                Ok(())
            }
            PathState::Validating { .. } => {
                Err(Error::Internal("Path still being validated".to_string()))
            }
            PathState::Failed { reason, .. } => {
                Err(Error::Internal(format!("Path validation failed: {}", reason)))
            }
        }
    }

    /// Get the current active path
    pub async fn get_active_path(&self) -> Result<PathInfo> {
        let active_id = *self.active_path_id.lock().await;
        let paths = self.paths.lock().await;
        
        paths.get(&active_id)
            .cloned()
            .ok_or_else(|| Error::Internal("Active path not found".to_string()))
    }

    /// Check for path validation timeouts
    pub async fn check_validation_timeouts(&self) -> Vec<u64> {
        let mut paths = self.paths.lock().await;
        let mut failed_paths = Vec::new();
        let now = Instant::now();

        for (path_id, path_info) in paths.iter_mut() {
            if let PathState::Validating { started_at, attempts, .. } = &path_info.state {
                if now.duration_since(*started_at) > self.config.validation_timeout {
                    if *attempts >= self.config.max_validation_attempts {
                        // Copy values before modification to avoid borrow issues
                        let path_id_copy = *path_id;
                        let attempts_copy = *attempts;
                        
                        path_info.state = PathState::Failed {
                            reason: "Validation timeout".to_string(),
                            failed_at: now,
                        };
                        failed_paths.push(path_id_copy);

                        protocol_event!(
                            Level::Warn,
                            "Path validation failed";
                            "path_id" => path_id_copy,
                            "reason" => "timeout",
                            "attempts" => attempts_copy
                        );
                    }
                }
            }
        }

        failed_paths
    }

    /// Retire a path
    pub async fn retire_path(&self, path_id: u64) -> Result<()> {
        let mut paths = self.paths.lock().await;
        
        // Can't retire the active path
        let active_id = *self.active_path_id.lock().await;
        if path_id == active_id {
            return Err(Error::Internal("Cannot retire active path".to_string()));
        }

        if paths.remove(&path_id).is_some() {
            protocol_event!(
                Level::Info,
                "Path retired";
                "path_id" => path_id
            );
            Ok(())
        } else {
            Err(Error::Internal("Path not found".to_string()))
        }
    }

    /// Get all paths
    pub async fn get_all_paths(&self) -> Vec<PathInfo> {
        let paths = self.paths.lock().await;
        paths.values().cloned().collect()
    }

    /// Update path MTU after successful probe
    pub async fn update_path_mtu(&self, path_id: u64, new_mtu: usize) -> Result<()> {
        let mut paths = self.paths.lock().await;
        
        if let Some(path) = paths.get_mut(&path_id) {
            path.max_packet_size = new_mtu;
            
            protocol_event!(
                Level::Debug,
                "Path MTU updated";
                "path_id" => path_id,
                "new_mtu" => new_mtu
            );
            
            Ok(())
        } else {
            Err(Error::Internal("Path not found".to_string()))
        }
    }

    /// Check if migration is needed based on network changes
    pub async fn check_migration_needed(&self, current_local: SocketAddr) -> bool {
        if !self.config.enable_auto_migration {
            return false;
        }

        let paths = self.paths.lock().await;
        let active_id = *self.active_path_id.lock().await;
        
        if let Some(active_path) = paths.get(&active_id) {
            // Migration needed if local address changed
            active_path.local_addr != current_local
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_migration_manager_creation() {
        let config = MigrationConfig::default();
        let manager = MigrationManager::new(config);
        
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        
        let path_id = manager.init_primary_path(local, remote).await.unwrap();
        assert_eq!(path_id, 0);
        
        let active_path = manager.get_active_path().await.unwrap();
        assert_eq!(active_path.local_addr, local);
        assert_eq!(active_path.remote_addr, remote);
    }

    #[tokio::test]
    async fn test_path_validation() {
        let config = MigrationConfig::default();
        let manager = MigrationManager::new(config);
        
        let local1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        
        manager.init_primary_path(local1, remote1).await.unwrap();
        
        // Start validation for a new path
        let local2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8080);
        let remote2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8081);
        
        let (path_id, challenge) = manager.start_path_validation(local2, remote2).await.unwrap();
        assert_eq!(path_id, 1);
        assert_eq!(challenge.len(), 8);
        
        // Simulate PATH_RESPONSE
        let validated_path = manager.handle_path_response(&challenge, remote2).await.unwrap();
        assert_eq!(validated_path, Some(1));
    }

    #[tokio::test]
    async fn test_connection_migration() {
        let config = MigrationConfig::default();
        let manager = MigrationManager::new(config);
        
        let local1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        
        manager.init_primary_path(local1, remote1).await.unwrap();
        
        // Add and validate a new path
        let local2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8080);
        let remote2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8081);
        
        let (path_id, challenge) = manager.start_path_validation(local2, remote2).await.unwrap();
        manager.handle_path_response(&challenge, remote2).await.unwrap();
        
        // Migrate to the new path
        manager.migrate_to_path(path_id).await.unwrap();
        
        let active_path = manager.get_active_path().await.unwrap();
        assert_eq!(active_path.path_id, path_id);
        assert_eq!(active_path.remote_addr, remote2);
    }
}