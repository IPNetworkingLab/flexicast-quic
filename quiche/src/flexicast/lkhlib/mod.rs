pub mod lkh;
pub mod node;
pub mod user;
pub mod tree;
pub mod packet;
pub mod lkhcrypto;

pub const FCSIMPLEKEY:u8 = 0;
pub const FCUNPROTECTEDKEY:u8 = 1;
pub const FCPROTECTEDKEY:u8 = 2;
pub const MC_KEY_LKH_CODE:u64 = 0xbeeffeeb; 