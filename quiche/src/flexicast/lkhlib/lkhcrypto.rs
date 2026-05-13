
use crate::crypto::{Open,Seal,Algorithm};
use crate::flexicast::lkhlib::packet::{KeylessWrappedKeyUpdatePacket,WrappedKeyUpdatePacket,KeyUpdatePacket};

pub fn lkh_encrypt(packet: WrappedKeyUpdatePacket,algo:Algorithm) -> Result<KeylessWrappedKeyUpdatePacket> {
    
    
    let seal = Seal::from_secret(algo, &packet.ksk.clone())?;
    let buf = packet.packet.to_bytes();
    let data_len = buf.len();
    buf.resize(data_len+algo.tag_len(), 0);

    let ad = packet.ksk_id.to_be_bytes(); 

    seal.seal_with_u64_counter(0, 1, &ad, &buf, data_len, None)?;

    let out = KeylessWrappedKeyUpdatePacket {
        cipher : buf,
        ksk_id : packet.ksk_id
    };
    Ok(out)

}

pub fn lkh_decrypt(packet: KeylessWrappedKeyUpdatePacket, key:Vec<u8>, algo:Algorithm) -> Result<KeyUpdatePacket> {
    let open = Open::from_secret(algo, &key.clone())?;
    let cipher = packet.cipher.to_owned();
    let ad = packet.ksk_id.to_be_bytes();
    open.open_with_u64_counter(0, 1, &ad, &mut cipher);

    let out = KeyUpdatePacket::from_bytes(cipher).ok()?; 
    Ok(out)

}

