//use std::rc::Rc;
use std::fmt::{self};
use std::sync::Arc;
use crate::flexicast::lkhlib::user::User;
#[derive(Debug, PartialEq, Eq)]
/// Node object to be stored in a binary tree
pub struct Node {
    /// Location id in the tree (root at id=1)
    pub id: usize,
    /// Key vector
    pub key: Vec<u8>,
    /// Key identifier (must be kept between update)
    pub key_id: u64,
    /// User if the node is a leaf
    pub user: Option<Arc<User>>,
    /// Depth from the root
    pub depth: u64,
}

impl std::clone::Clone for Node {
    fn clone(&self) -> Self {
        Node {
            id: self.id,
            key: self.key.clone(),
            key_id: self.key_id,
            user: self.user.clone(),
            depth: self.depth,
        }
    }
}
impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hexkey: String = self.key.iter().map(|b| format!("{:02x}",b)).collect();//Gemini
        let _ = write!(f, "Node of key [{}]=>{} : ",self.key_id,hexkey);
        match &self.user  {
            None =>     write!(f,"None"),
            Some(user) => write!(f, "{:?},", user.user_id)
        }

        
        
    }
}

#[cfg(test)]
mod tests {
    
}
