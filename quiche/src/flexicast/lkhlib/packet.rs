#[derive(Clone,Debug)]
pub struct KeyUpdatePacket {
    pub new_key: Vec<u8>,
    pub new_key_id: u64,
    pub is_session_key: bool,
    pub delete_new_key: bool,
}
#[derive(Clone,Debug)]
pub struct WrappedKeyUpdatePacket {
    packet:KeyUpdatePacket,
    ksk:Vec<u8>,
    ksk_id : u64
}

impl KeyUpdatePacket {
    fn to_bytes(&self) -> Vec<u8> {
        let flags: u8 = (self.is_session_key as u8) | ((self.delete_new_key as u8) << 1);
        let mut out = vec![flags];
        out.extend_from_slice(self.new_key_id.to_be_bytes().as_ref());
        out.extend_from_slice(&self.new_key.clone());
        out
    }

    fn from_bytes(packet: Vec<u8>) -> Option<Self> {
        if packet.len() < 10 {
            None
        } else {
            let flags = packet[0];
            let is_session_key = (flags & 1) == 1;
            let delete_new_key = (flags & 2) == 2;

            let key_id: [u8; 8] = packet[1..9].try_into().ok()?;

            let id = u64::from_be_bytes(key_id);
            let key = packet[9..].to_vec();

            Some(KeyUpdatePacket {
                is_session_key,
                new_key: key,
                delete_new_key,
                new_key_id: id,
            })
        }
    }
    pub fn wrap(&self,ksk:Vec<u8>,ksk_id:u64) -> WrappedKeyUpdatePacket {
        WrappedKeyUpdatePacket { packet: self.clone(), ksk , ksk_id }
    }
}



impl WrappedKeyUpdatePacket {
    pub fn unwrap (&self) -> (Vec<u8>,u64, KeyUpdatePacket) {
        (self.ksk.clone(),self.ksk_id,self.packet.clone())
    }
}