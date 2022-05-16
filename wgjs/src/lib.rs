use wasm_bindgen::prelude::*;


/// C bindings for the BoringTun library
use boringtun::noise::{make_array, Tunn, TunnResult};
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use base64::{decode, encode};
use hex::encode as encode_hex;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic;
use std::ptr;
use std::ptr::null_mut;
use std::sync::{Arc, Once};
use std::thread;
use std::cell::RefCell;


thread_local!(
    static TUN_LIST: RefCell<Vec<Box<boringtun::noise::Tunn>>> = RefCell::new(Vec::new());
);

#[allow(non_camel_case_types)]
#[wasm_bindgen] 
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
/// Indicates the operation required from the caller
pub enum result_type {
    /// No operation is required.
    WIREGUARD_DONE = 0,
    /// Write dst buffer to network. Size indicates the number of bytes to write.
    WRITE_TO_NETWORK = 1,
    /// Some error occurred, no operation is required. Size indicates error code.
    WIREGUARD_ERROR = 2,
    /// Write dst buffer to the interface as an ipv4 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV4 = 4,
    /// Write dst buffer to the interface as an ipv6 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV6 = 6,
}

/// The return type of WireGuard functions
#[wasm_bindgen] 
pub struct wireguard_result {
    /// The operation to be performed by the caller
    pub op: result_type,
    /// Additional information, required to perform the operation
    pub size: usize,
}

#[wasm_bindgen]
pub struct stats {
    pub time_since_last_handshake: i64,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub estimated_loss: f32,
    pub estimated_rtt: i32,
    reserved: [u8; 56], // Make sure to add new fields in this space, keeping total size constant
}

impl<'a> From<TunnResult<'a>> for wireguard_result {
    fn from(res: TunnResult<'a>) -> wireguard_result {
        match res {
            TunnResult::Done => wireguard_result {
                op: result_type::WIREGUARD_DONE,
                size: 0,
            },
            TunnResult::Err(e) => wireguard_result {
                op: result_type::WIREGUARD_ERROR,
                size: e as _,
            },
            TunnResult::WriteToNetwork(b) => wireguard_result {
                op: result_type::WRITE_TO_NETWORK,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV4(b, _) => wireguard_result {
                op: result_type::WRITE_TO_TUNNEL_IPV4,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV6(b, _) => wireguard_result {
                op: result_type::WRITE_TO_TUNNEL_IPV6,
                size: b.len(),
            },
        }
    }
}

#[wasm_bindgen] 
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct x25519_key {
    pub key: *const [u8; 32],
}

/// Generates a new x25519 secret key.
#[no_mangle]
#[wasm_bindgen] 
pub fn x25519_secret_key() -> String  {
    let key = X25519SecretKey::new();
    return encode(key.as_bytes());
}

/// Computes a public x25519 key from a secret key.
#[no_mangle]
#[wasm_bindgen] 
pub fn x25519_public_key(private_key: &str) -> String {
    let private_key = private_key.parse::<X25519SecretKey>().unwrap();
    let pub_key = private_key.public_key();
    return encode(pub_key.as_bytes());
}



/// Check if the input C-string represents a valid base64 encoded x25519 key.
/// Return 1 if valid 0 otherwise.
#[no_mangle]
#[wasm_bindgen] 
pub fn check_base64_encoded_x25519_key(utf8_key: &str) -> i32 {
    if let Ok(key) = decode(&utf8_key) {
        let len = key.len();
        let mut zero = 0u8;
        for b in key {
            zero |= b
        }
        if len == 32 && zero != 0 {
            1
        } else {
            0
        }
    } else {
        0
    }
}

/// Allocate a new tunnel, return NULL on failure.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
#[wasm_bindgen] 
pub fn new_tunnel(
    static_private: &str,
    server_static_public: &str,
    preshared_key: &str,
    keep_alive: u16,
    index: u32,
) -> i32 {

    let preshared_key = {
        if let Ok(key) = preshared_key.parse::<X25519PublicKey>() {
                Some(make_array(key.as_bytes()))
            } else {
                return -1;
            }
    };

    let private_key = match static_private.parse() {
        Err(_) => return -1,
        Ok(key) => key,
    };

    let public_key = match server_static_public.parse() {
        Err(_) => return -1,
        Ok(key) => key,
    };

    let keep_alive = if keep_alive == 0 {
        None
    } else {
        Some(keep_alive)
    };

    let tunnel = match Tunn::new(
        Arc::new(private_key),
        Arc::new(public_key),
        preshared_key,
        keep_alive,
        index,
        None,
    ) {
        Ok(t) => t,
        Err(_) => return -1,
    };
    let mut out = 0;
    TUN_LIST.with(|list| {
        let mut tunnel_list = list.borrow_mut(); 
        tunnel_list.push(tunnel);
        out = tunnel_list.len() as i32 -1;
    });
    return out as i32;
}

/// Write an IP packet from the tunnel interface.
/// For more details check noise::tunnel_to_network functions.
#[no_mangle]
#[wasm_bindgen] 
pub fn wireguard_write(
    tunnel: usize,
    src: &mut [u8],
    dst: &mut [u8],
) -> wireguard_result {
    let mut res : wireguard_result = wireguard_result::from(TunnResult::Done);
    TUN_LIST.with(|list| {
        let mut tunnel_list = list.borrow_mut();
        let tunnel = tunnel_list.get_mut(tunnel).unwrap();
        res = wireguard_result::from(tunnel.encapsulate(src, dst))
    });
    return res;
}

/// Read a UDP packet from the server.
/// For more details check noise::network_to_tunnel functions.
#[no_mangle]
#[wasm_bindgen] 
pub fn wireguard_read(
    tunnel: usize,
    src: &mut [u8],
    dst: &mut [u8],
) -> wireguard_result {
    let mut res : wireguard_result = wireguard_result::from(TunnResult::Done);
    TUN_LIST.with(|list| {
        let mut tunnel_list = list.borrow_mut();
        let tunnel = tunnel_list.get_mut(tunnel).unwrap();
        res = wireguard_result::from(tunnel.decapsulate(None, src, dst))
    });
    return res;
}

/// This is a state keeping function, that need to be called periodically.
/// Recommended interval: 100ms.
#[no_mangle]
#[wasm_bindgen] 
pub fn wireguard_tick(
    tunnel: usize,
    dst: &mut [u8],
) -> wireguard_result {
    let mut res : wireguard_result = wireguard_result::from(TunnResult::Done);
    TUN_LIST.with(|list| {
        let mut tunnel_list = list.borrow_mut();
        let tunnel = tunnel_list.get_mut(tunnel).unwrap();
        res =wireguard_result::from(tunnel.update_timers(dst));
    });
    return res;
}

/// Force the tunnel to initiate a new handshake, dst buffer must be at least 148 byte long.
#[no_mangle]
#[wasm_bindgen] 
pub fn wireguard_force_handshake(
    tunnel: usize,
    dst:  &mut [u8],
) -> wireguard_result {
    let mut res : wireguard_result = wireguard_result::from(TunnResult::Done);
    TUN_LIST.with(|list| {
        let mut tunnel_list = list.borrow_mut();
        let tunnel = tunnel_list.get_mut(tunnel).unwrap();
        res = wireguard_result::from(tunnel.format_handshake_initiation(dst, true))
    });
    return res;
}

/// Returns stats from the tunnel:
/// Time of last handshake in seconds (or -1 if no handshake occurred)
/// Number of data bytes encapsulated
/// Number of data bytes decapsulated
#[no_mangle]
#[wasm_bindgen] 
pub fn wireguard_stats(tunnel: usize) -> stats {
    let mut stats = stats {
        time_since_last_handshake: 0,
        tx_bytes: 0,
        rx_bytes: 0,
        estimated_loss: 0.0,
        estimated_rtt: 0,
        reserved: [0u8; 56]
    };
    TUN_LIST.with(|list| {
        let mut tunnel_list = list.borrow_mut();
        let tunnel = tunnel_list.get_mut(tunnel).unwrap();
        let (time, tx_bytes, rx_bytes, estimated_loss, estimated_rtt) = tunnel.stats();
        stats = stats {
            time_since_last_handshake: time.map(|t| t as i64).unwrap_or(-1),
            tx_bytes,
            rx_bytes,
            estimated_loss,
            estimated_rtt: estimated_rtt.map(|r| r as i32).unwrap_or(-1),
            reserved: [0u8; 56],
        }
    });
    return stats;
}


