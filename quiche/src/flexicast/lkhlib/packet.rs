#[derive(Clone, Debug, PartialEq, Eq)]
/// Raw key update packet
pub struct KeyUpdatePacket {
    /// The updated key vector
    pub new_key: Vec<u8>,
    /// The identifier designating the updated key
    pub new_key_id: u64,
    /// Should the updated key be the considered as the new session key
    pub is_session_key: bool,
    /// Should this key be removed from the list of keys of the receiver
    pub delete_new_key: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// A cleartext key update packet associated with a key signing key
pub struct WrappedKeyUpdatePacket {
    /// The raw key update
    pub packet: KeyUpdatePacket,
    /// the key signing key vector
    pub ksk: Vec<u8>,
    /// the key signing key identifier
    pub ksk_id: u64,

}
#[derive(Clone, Debug, PartialEq, Eq)]
/// An encrypted key update packet using the key signging key designated by `ksk_id`
pub struct KeylessWrappedKeyUpdatePacket {
    /// the ciphertext containing the key update packet
    pub cipher: Vec<u8>,
    /// the counter used to avoid replay
    pub counter: u64,
    /// the key identifier of the key used to encrypt the packet
    pub ksk_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Enum listing the different possible type of key update packet
pub enum FCKeyUpdate {
    /// Raw key
    RawKey(Vec<u8>),
    /// Raw tree key update
    KeyUpdate(KeyUpdatePacket),
    /// Key update to be wrapped with ksk
    //WrappedKeyUpdatePacket(WrappedKeyUpdatePacket),
    /// key update that couldn't yet be deciphered
    KeylessWrappedKeyUpdate(KeylessWrappedKeyUpdatePacket),
}

impl KeyUpdatePacket {
    /// Serialize a key update packet
    pub fn to_bytes(&self) -> Vec<u8> {
        let flags: u8 =
            (self.is_session_key as u8) | ((self.delete_new_key as u8) << 1);
        let mut out = vec![flags];
        out.extend_from_slice(self.new_key_id.to_be_bytes().as_ref());
        let len = (self.new_key.len() as u32).to_be_bytes();
        out.extend_from_slice(&len);
        out.extend_from_slice(&self.new_key.clone());
        out
    }
    /// Deserialize a key update packet
    pub fn from_bytes(packet: Vec<u8>) -> Option<Self> {
        if packet.len() < 10 {
            None
        } else {
            let flags = packet[0];
            let is_session_key = (flags & 1) == 1;
            let delete_new_key = (flags & 2) == 2;

            let key_id: [u8; 8] = packet[1..9].try_into().ok()?;

            let id = u64::from_be_bytes(key_id);
            let key_len = u32::from_be_bytes(packet[9..13].try_into().ok()?);
            if packet.len() < (13 + key_len as usize) {
                None
            } else {
                let key = packet[13..(13 + key_len as usize)].to_vec();

                Some(KeyUpdatePacket {
                    is_session_key,
                    new_key: key,
                    delete_new_key,
                    new_key_id: id,
                })
            }
        }
    }
    /// Utility function to add the key signing key to be used for encryption of this packet
    pub fn wrap(
        &self, ksk: Vec<u8>, ksk_id: u64, 
    ) -> WrappedKeyUpdatePacket {
        WrappedKeyUpdatePacket {
            packet: self.clone(),
            ksk,
            ksk_id,
            
        }
    }
}

impl WrappedKeyUpdatePacket {
    /// Utility function returning the ksk, ksk identifier and raw key update packet
    pub fn unwrap(&self) -> (Vec<u8>, u64, KeyUpdatePacket) {
        (self.ksk.clone(), self.ksk_id, self.packet.clone())
    }
}

impl KeylessWrappedKeyUpdatePacket {
    /// Serialize a keyless wrapped key update
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.cipher.len() + 8 + 4);
        out.extend_from_slice(&self.ksk_id.to_be_bytes());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.cipher);
        out
    }
    /// Deserialize a keyless wrapped key update
    pub fn from_bytes(packet: Vec<u8>) -> Option<Self> {
        let ksk_idb: [u8; 8] = packet[..8].try_into().ok()?;
        let counterb: [u8; 8] = packet[8..16].try_into().ok()?;
        let counter = u64::from_be_bytes(counterb);
        let ksk_id = u64::from_be_bytes(ksk_idb);
        let cipher = packet[16..].to_vec();
        Some(KeylessWrappedKeyUpdatePacket { cipher, ksk_id, counter })
    }
}
