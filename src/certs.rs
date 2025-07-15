//! Certificate loading utilities for testing

use crate::error::{Error, Result};
use rustls::{pki_types::{CertificateDer, PrivateKeyDer}, RootCertStore};
use std::{fs::File, io::BufReader, path::Path};

/// Load a certificate chain from a PEM file
pub fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path.as_ref())
        .map_err(|e| Error::Config(format!("Failed to open cert file: {}", e)))?;
    let mut reader = BufReader::new(file);
    
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("Failed to parse certificates: {}", e)))?;
    
    Ok(certs)
}

/// Load a private key from a PEM file
pub fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path.as_ref())
        .map_err(|e| Error::Config(format!("Failed to open key file: {}", e)))?;
    let mut reader = BufReader::new(file);
    
    // Try different key formats
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| Error::Config(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| Error::Config("No private key found in file".to_string()))?;
    
    Ok(key)
}

/// Create a root certificate store from a certificate file
pub fn load_root_certs(path: impl AsRef<Path>) -> Result<RootCertStore> {
    let certs = load_certs(path)?;
    let mut root_store = RootCertStore::empty();
    
    for cert in certs {
        root_store.add(cert)
            .map_err(|e| Error::Config(format!("Failed to add root certificate: {}", e)))?;
    }
    
    Ok(root_store)
}

/// Get the path to test certificates
pub fn test_cert_path(filename: &str) -> String {
    format!("certs/{}", filename)
}