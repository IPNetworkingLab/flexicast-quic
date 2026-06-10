use crate::Error;
use crate::crypto::{Algorithm, Open, Seal};

use crate::flexicast::lkhlib::packet::{
    KeyUpdatePacket, KeylessWrappedKeyUpdatePacket, WrappedKeyUpdatePacket,
};
/// Encrypt a key update packet to be sent on the multicast
pub fn lkh_encrypt(
    packet: WrappedKeyUpdatePacket, algo: Algorithm, counter:u64
) -> Result<KeylessWrappedKeyUpdatePacket,crate::Error> {
    let seal = Seal::from_secret(algo, &packet.ksk.clone())?;
    println!("{seal:?}");
    let mut buf = packet.packet.to_bytes();
    let data_len = buf.len();
    buf.resize(data_len + algo.tag_len(), 0);

    let ad = packet.ksk_id.to_be_bytes();

    seal.seal_with_u64_counter(0, counter, &ad, &mut buf, data_len, None)?;

    let out = KeylessWrappedKeyUpdatePacket {
        cipher: buf,
        ksk_id: packet.ksk_id,
        counter:counter,
    };
    Ok(out)
}
/// decrypt a key update received from the multicast
pub fn lkh_decrypt(
    packet: KeylessWrappedKeyUpdatePacket, key: Vec<u8>, algo: Algorithm,
) -> Result<KeyUpdatePacket,crate::Error> {
    let open = Open::from_secret(algo, &key.clone())?;
    println!("{open:?}");
    let mut cipher = packet.cipher.to_owned();
    let ad = packet.ksk_id.to_be_bytes();
    
    open.open_with_u64_counter(0, packet.counter, &ad, &mut cipher)?;

    let out = KeyUpdatePacket::from_bytes(cipher).ok_or(Error::CryptoFail)?;
    Ok(out)
}

#[cfg(test)]
mod testing {
    use super::*;

    //use crate::rand::{rand_bytes, rand_u64};
    #[test]
    fn test_encrypt_decrypt() {
        for algo in [Algorithm::AES128_GCM,Algorithm::AES256_GCM,Algorithm::ChaCha20_Poly1305] {
            let mut new_key = Vec::new();
            new_key.resize(algo.key_len(), 0);
            let new_key_id = 42 as u64;
            let mut ksk =Vec::new();
            ksk.resize(algo.key_len(), 1);
            let ksk_id = 32 as u64;
            let packet = KeyUpdatePacket {
                delete_new_key:false,
                is_session_key: false,
                 new_key:new_key,
                 new_key_id:new_key_id
            };
            let wrapped = packet.wrap(ksk.clone(), ksk_id);

            let cipher = lkh_encrypt(wrapped, algo,1).unwrap();
            
            let clear = lkh_decrypt(cipher, ksk, algo).unwrap();

            assert_eq!(clear,packet);
            
        }
    }
}
