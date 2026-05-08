use crate::flexicast::lkhlib::packet::KeyUpdatePacket;

pub struct User {
    pub user_id: String,
    pub send: Box<dyn Fn(KeyUpdatePacket) + Send + Sync>,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "User [{}]", self.user_id)
    }
}

impl std::cmp::PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.user_id == other.user_id
    }
}
impl std::cmp::Eq for User {}


