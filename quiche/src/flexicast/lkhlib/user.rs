use crate::flexicast::lkhlib::packet::KeyUpdatePacket;
/// Struct to store a user : 
///     - user_id : a byte vector that must be unique a specific user
///     - send : a function to send a key update to a specific user (assumed to be encrypted)
pub struct User {
    /// user_id : a byte vector that must be unique a specific user
    pub user_id: Vec<u8>,
    /// send : a function to send a key update to a specific user (assumed to be encrypted)
    pub send: Box<dyn Fn(KeyUpdatePacket) + Send + Sync>,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "User [{:?}]", self.user_id)
    }
}

impl std::cmp::PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.user_id == other.user_id
    }
}
impl std::cmp::Eq for User {}



