/// Main module handling the logic for Logical Key Hierarchy
pub mod lkh;
/// Node used in the tree
pub mod node;
/// Users used in the node
pub mod user;
/// All things related to the usage of the tree 
pub mod tree;
/// general key update packet specs
pub mod packet;
/// Implementation specific packet to encrypt/decrypt key update packet
pub mod lkhcrypto;
/// Plaintext key update (without a keyid)
pub const FCSIMPLEKEY:u8 = 0;
/// Plaintext key update (with a keyid)
pub const FCUNPROTECTEDKEY:u8 = 1;
/// Encrypted key update
pub const FCPROTECTEDKEY:u8 = 2;
/// Frame identifier code
pub const MC_KEY_LKH_CODE:u64 = 0xbeeffeeb; 