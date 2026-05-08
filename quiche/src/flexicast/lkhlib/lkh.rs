

use crate::flexicast::lkhlib::node::Node;
use crate::flexicast::lkhlib::packet::{KeyUpdatePacket, WrappedKeyUpdatePacket};
use crate::flexicast::lkhlib::tree::{BinaryTree, Tree};
use crate::flexicast::lkhlib::user::User;


use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;


//TODO: change the user_id to an int ?
pub trait LogicalTree {
    ///Add a user designated by `user_id` and a fonction `send` that send a vec8 to the user.
    fn add_user(&mut self, user_id: String, send: Box<dyn Fn(KeyUpdatePacket) + Send + Sync>) -> ();
    ///Remove a user designated by `user_id`
    fn remove_user(&mut self, user_id: &str) -> ();
    ///Return a tuple `(key_id, key)` if possible
    fn get_session_key(&self) -> Option<(u64, &[u8])>;
}

pub struct Lkh {
    tree: Tree,
    //users: HashMap<String, usize>, //Delegated to Tree
    key_size: usize,
    send_group: Box<dyn Fn(WrappedKeyUpdatePacket) + Send + Sync>,
}

impl std::fmt::Debug for Lkh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LKH Tree of {} users using key of length [{}] : \n{}",
            self.tree.get_user_count(),
            self.key_size,
            self.tree
        )
    }
}

impl Lkh {
    fn get_user_count(&self) -> usize {
        self.tree.get_user_count()
    }
    fn generate_key_id(&self) -> u64 {
        // Generate a unique key ID (for simplicity, using a random number here)
        let mut key_id_bytes = [0u8; 8];
        //rand_bytes(&mut key_id_bytes).expect("Failed to generate random key ID");
        crate::rand::rand_bytes(&mut key_id_bytes);
        u64::from_be_bytes(key_id_bytes)
    }
    fn generate_key(&self) -> Vec<u8> {
        let mut key = vec![0u8; self.key_size];
        crate::rand::rand_bytes(&mut key);
        key
    }

    fn update_keys(&mut self, node_id: usize, already_updated: &mut HashSet<usize>) {
        // Update keys along the path from the new node to the root
        let mut current_id = node_id;
        let is_carrying_user = self
            .tree
            .get_node_by_id(node_id)
            .as_ref()
            .is_some_and(|node| node.user.is_some());
        let mut path: Vec<(u64, Vec<u8>)> = Vec::new();

        //We also need to update the parent key_id, assuming that there is a parent

        let parent = self.tree.get_parent(node_id);
        match parent {
            None => (),
            Some(node) => {
                let parent_id = node.id;
                self.tree.get_node_by_id_mut(parent_id).expect("msg").key_id =
                    self.generate_key_id();
            }
        }

        loop {
            if already_updated.contains(&current_id) {
                println!("In untestedbranch");
                let (keyid, key, parent_id) = {
                    let node = self
                        .tree
                        .get_node_by_id(current_id)
                        .expect("Node not found");

                    let keyid = node.key_id;
                    let key = node.key.clone();

                    let next_id = self.tree.get_parent(current_id).as_ref().map(|n| n.id);
                    (keyid, key, next_id)
                };

                match parent_id {
                    None => break,
                    Some(next_node_id) => current_id = next_node_id,
                }
                path.push((keyid, key));
                continue;
            }
            let new_key = self.generate_key();
            let current = self.tree.get_node_by_id_mut(current_id);
            let is_leaf = match current {
                None => break,
                Some(node) => {
                    let _old_key = node.key.clone();

                    path.push((node.key_id, new_key.clone()));
                    node.key = new_key;
                    node.user.is_some()
                }
            };
            if !is_leaf {
                self.send_key_to_children(current_id);
            }

            current_id = match self.tree.get_parent(current_id) {
                None => break,
                Some(node) => node.id,
            };
        }

        if is_carrying_user {
            self.send_key_by_unicast(node_id, path);
        }
    }

    fn send_key_to_children(&self, node_id: usize) {
        // Send the new key to all children of the updated node
        //TODO : implement
        #[cfg(feature = "debug")]
        {
            println!(
                "Sending new key of node {} to its children if they exist",
                node_id
            );
        }

        let session_key_id = self
            .tree
            .get_root()
            .expect("Trying to update an empty tree")
            .key_id;

        let (new_key, key_id) = match self.tree.get_node_by_id(node_id) {
            None => return,
            Some(node) => {
                let new_key = node.key.clone();
                let key_id = node.key_id;
                (new_key, key_id)
            }
        };

        let packet = KeyUpdatePacket {
            new_key,
            new_key_id: key_id,
            is_session_key: key_id == session_key_id,
            delete_new_key: false,
        };

        match self.tree.get_left_child(node_id) {
            None => (),
            Some(node) => {
                let ksk = &node.key;
                let ksk_id = node.key_id;
                #[cfg(feature = "debug")]
                {
                    println!(
                        "Sending new key to left child : {} with key {}",
                        node.id, ksk_id
                    );
                }
                let to_send = packet.wrap(ksk.to_vec(), ksk_id);
                (self.send_group)(to_send);
            }
        };
        match self.tree.get_right_child(node_id) {
            None => (),
            Some(node) => {
                let ksk = &node.key;
                let ksk_id = node.key_id;
                #[cfg(feature = "debug")]
                {
                    println!(
                        "Sending new key to right child : {} with key {}",
                        node.id, ksk_id
                    );
                }
                let to_send = packet.wrap(ksk.to_vec(), ksk_id);
                (self.send_group)(to_send);
            }
        };
    }

    fn send_key_by_unicast(&self, node_id: usize, path: Vec<(u64, Vec<u8>)>) {
        // Send the new key to the user of the updated node by unicast

        let session_key_id = self
            .tree
            .get_root()
            .expect("Trying to update a node in a tree without root")
            .key_id;

        for i in path.iter() {
            let key_id = i.0;
            let key = i.1.clone();
            let should_delete = false;
            let is_sessions_key = key_id == session_key_id;
            let packet = KeyUpdatePacket {
                new_key: key,
                new_key_id: key_id,
                is_session_key: is_sessions_key,
                delete_new_key: should_delete,
            };
            let node = self.tree.get_node_by_id(node_id);
            #[cfg(feature = "debug")]
            {
                println!(
                    "Sending key {key_id} to {0} [{1:x?}]",
                    node.expect("Wrong node").id,
                    i.1
                )
            }
            (node
                .expect("Trying to send to a non existing node")
                .user
                .as_ref()
                .expect("Trying to update the key of a non existing user")
                .as_ref()
                .send)(packet);
        }
    }

    fn update_keys_by_layer(&mut self, added_nodes: Vec<usize>) {
        let session_key_id = self.tree.get_root().map(|node| node.key_id);
        let mut to_visit = HashMap::new();
        let mut already_updated = HashSet::new();
        for node_id in added_nodes {
            let node = self
                .tree
                .get_node_by_id(node_id)
                .expect("Not couldn't be added");
            let packet = KeyUpdatePacket {
                new_key: node.key.clone(),
                new_key_id: node.key_id,
                is_session_key: match session_key_id {
                    None => false,
                    Some(id) => id == node.key_id,
                },
                delete_new_key: false,
            };

            let user = node.user.as_ref().expect("Added node doesn't have a user");
            (user.send)(packet);

            match self.tree.get_parent(node_id) {
                None => (),
                Some(parent) => {
                    to_visit
                        .entry(parent.depth)
                        .or_insert(HashSet::new())
                        .insert(parent.id);
                }
            }
            already_updated.insert(node_id);
        }

        while !to_visit.is_empty() {
            let max_depth = to_visit.keys().max().copied();
            if max_depth.is_none() {
                break;
            }
            let max_depth = max_depth.unwrap();
            let layer = to_visit.remove(&max_depth).expect("Missing layer");
            for node_id in layer {
                if !already_updated.contains(&node_id) {
                    let new_key = self.generate_key();
                    let node = self
                        .tree
                        .get_node_by_id_mut(node_id)
                        .expect("Node in path to root doesn't exist");
                    node.key = new_key;

                    self.send_key_to_children(node_id);

                    match self.tree.get_parent(node_id) {
                        None => (),
                        Some(parent) => {
                            to_visit
                                .entry(parent.depth)
                                .or_insert(HashSet::new())
                                .insert(parent.id);
                        }
                    };
                    already_updated.insert(node_id);
                }
            }
        }
    }
    pub fn add_user_vec(&mut self, users: Vec<User>) {
        let _already_updated: HashSet<usize> = HashSet::new();
        //Update in 2 steps, add everyone in the tree then update the keys by starting with the deepest one.
        let user_ids: Vec<String> = users.iter().map(|u| u.user_id.clone()).collect();

        for user in users {
            let node = Node {
                id: 0,
                key: self.generate_key(),
                key_id: self.generate_key_id(),
                user: Some(Arc::new(user)),
                depth: 0,
            };
            let id = self.tree.add_node(node);
            if id > 1 {
                let parent_id = self
                    .tree
                    .get_parent(id)
                    .as_ref()
                    .expect("not root but no parent")
                    .id;
                self.tree
                    .get_node_by_id_mut(parent_id)
                    .expect("not root but no parent")
                    .key_id = self.generate_key_id();
            }
        }

        let mut added_nodes: Vec<usize> = Vec::new();
        for user_id in user_ids {
            let node_id = self
                .tree
                .get_user_node(&user_id)
                .expect("Node wasn't successfully inserted");
            added_nodes.push(*node_id);
        }

        #[cfg(feature = "debug")]
        {
            println!("Current tree before update {}", self.tree);
        }
        self.update_keys_by_layer(added_nodes);
    }
}

impl LogicalTree for Lkh {
    fn remove_user(&mut self, user_id: &str) {
        let session_key_id = self
            .tree
            .get_root()
            .expect("Trying to remove a node from an empty tree")
            .key_id;

        let node_id = match self.tree.get_user_node(user_id) {
            None => return,
            Some(id) => *id,
        };
        let node = match self.tree.get_node_by_id(node_id) {
            None => return,
            Some(node) => node,
        };
        let key_to_delete = node.key.clone();
        let key_id_to_delete = node.key_id;

        let packet = KeyUpdatePacket {
            new_key: key_to_delete.clone(),
            new_key_id: key_id_to_delete,
            delete_new_key: true,
            is_session_key: key_id_to_delete == session_key_id,
        };

        let to_send = packet.wrap(key_to_delete, key_id_to_delete);
        (self.send_group)(to_send);

        match self.tree.get_parent(node_id) {
            None => (),
            Some(node) => {
                let key_to_delete = node.key.clone();
                let key_id_to_delete = node.key_id;

                let packet = KeyUpdatePacket {
                    new_key: key_to_delete.clone(),
                    new_key_id: key_id_to_delete,
                    delete_new_key: true,
                    is_session_key: key_id_to_delete == session_key_id,
                };

                let to_send = packet.wrap(key_to_delete, key_id_to_delete);
                (self.send_group)(to_send);
            }
        };

        let merged_node = self.tree.merge_nodes(node_id);

        match merged_node {
            0 => (),
            _ => {
                self.update_keys(merged_node, &mut HashSet::new());
            }
        }
    }
    fn add_user(&mut self, user_id: String, send: Box<dyn Fn(KeyUpdatePacket) +Send + Sync>) {
        let user = User {
            user_id: user_id.clone(),
            send,
        };
        let node = Node {
            id: 0,
            key: self.generate_key(),
            key_id: self.generate_key_id(),
            user: Some(Arc::new(user)),
            depth: 0,
        };
        let new_id = self.tree.add_node(node);
        self.update_keys(new_id, &mut HashSet::new());
    }
    fn get_session_key(&self) -> Option<(u64, &[u8])> {
        self.tree.get_root().map(|u| (u.key_id, u.key.as_slice()))
    }
}
#[derive(Debug)]
pub struct LKHPlus {
    lkh: Lkh,
    unordered_users: HashMap<String, User>,
    max_unordered_count: usize,
}

impl fmt::Display for LKHPlus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "LKH+ :\n\tMax unordered users : {}\n\t unordered users {:?}\n\t tree : {:?}",
            self.max_unordered_count, self.unordered_users, self.lkh
        )
    }
}

impl LogicalTree for LKHPlus {
    fn get_session_key(&self) -> Option<(u64, &[u8])> {
        self.lkh.get_session_key()
    }

    fn add_user(&mut self, user_id: String, send: Box<dyn Fn(KeyUpdatePacket)+ Send + Sync>) {
        if self.lkh.get_user_count() == 0 {
            self.lkh.add_user(user_id, send);
        } else {
            let new_key = self.lkh.generate_key();
            if self.unordered_users.len() + 1 < self.max_unordered_count {
                let root = self.lkh.tree.get_node_by_id_mut(1).expect("Missing root");
                let old_key = root.key.clone();
                let key_id = root.key_id;
                root.key = new_key.clone();

                let packet = KeyUpdatePacket {
                    new_key,
                    new_key_id: key_id,
                    is_session_key: true,
                    delete_new_key: false,
                };

                (self.lkh.send_group)(packet.wrap(old_key, key_id));
                (send)(packet);
                let new_user = User {
                    user_id: user_id.clone(),
                    send,
                };
                self.unordered_users.insert(user_id, new_user);
            } else {
                let new_user = User {
                    user_id: user_id.clone(),
                    send,
                };
                self.unordered_users.insert(user_id, new_user);
                self.lkh
                    .add_user_vec(self.unordered_users.drain().map(|u| u.1).collect());
            }
        }
    }
    fn remove_user(&mut self, user_id: &str) {
        if self.unordered_users.contains_key(user_id) {
            let removed_user = self.unordered_users.remove(user_id).unwrap();
            let new_key = self.lkh.generate_key();
            let root = self.lkh.tree.get_node_by_id_mut(1).expect("missing root");

            let old_key = root.key.clone();
            let key_id = root.key_id;
            root.key = new_key.clone();

            let packet = KeyUpdatePacket {
                new_key,
                new_key_id: key_id,
                is_session_key: true,
                delete_new_key: false,
            };
            if let Some(root_user) = &root.user {
                (root_user.send)(packet.clone());
            }
            self.lkh.send_key_to_children(1);
            for (_, user) in self.unordered_users.iter() {
                (user.send)(packet.clone());
            }
            let remove_packet = KeyUpdatePacket {
                new_key: old_key,
                new_key_id: key_id,
                is_session_key: true,
                delete_new_key: true,
            };

            (removed_user.send)(remove_packet);
        } else {
            self.lkh.remove_user(user_id);

            if self.lkh.get_user_count() == 0 {
                //We need to change the root
                self.lkh
                    .add_user_vec(self.unordered_users.drain().map(|u| u.1).collect());
            } else {
                let root = self.lkh.tree.get_root().unwrap();
                let key = root.key.clone();
                let key_id = root.key_id;
                let packet = KeyUpdatePacket {
                    new_key: key,
                    new_key_id: key_id,
                    is_session_key: true,
                    delete_new_key: false,
                };

                for (_, user) in self.unordered_users.iter() {
                    (user.send)(packet.clone())
                }
            }
        }
    }
}

//-------------------------------------TEST-------------------------------------------------
struct TestUser {
    user_id: String,
    keys: HashMap<u64, Vec<u8>>,
    key_len: usize,
    session_key_id: Option<u64>,
    in_tree: bool,
}

impl fmt::Debug for TestUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TestUser [{}] : ", self.user_id).ok();
        for (key_id, key) in self.keys.iter() {
            write!(f, "\n\t").ok();
            if self.session_key_id.is_some() && self.session_key_id.unwrap() == *key_id {
                write!(f, "\x1b[93m(Session Key)\x1b[0m ").ok();
            }
            let hexkey: String = key.iter().map(|b| format!("{:02x}", b)).collect(); //Gemini
            write!(f, "Key {} : {}", key_id, hexkey).ok();
        }
        Ok(())
    }
}

impl TestUser {
    fn receive_single(&mut self, packet: KeyUpdatePacket) {
        if packet.delete_new_key {
            self.keys.remove(&packet.new_key_id);
            if packet.is_session_key {
                self.session_key_id = None;
            }
        } else {
            #[cfg(feature = "debug")]
            {
                println!(
                    "User {} updated key {} with new key {:?}",
                    self.user_id, packet.new_key_id, packet.new_key
                );
            }
            self.keys.insert(packet.new_key_id, packet.new_key);
            if packet.is_session_key {
                self.session_key_id = Some(packet.new_key_id);
            }
        }
    }

    fn receive_group(&mut self, wrapped: WrappedKeyUpdatePacket) {
        //data : ksk_id,iv,tag,cipher
        #[cfg(feature = "debug")]
        {
            println!("User {} received group data", self.user_id,);

            println!("Availables keys: {:?}", self.keys);
        }

        let (ksk, ksk_id, packet) = wrapped.unwrap();
        if !self.keys.contains_key(&ksk_id) || self.keys[&ksk_id] != ksk  {
            //Shouldn't be able to decipher it
            return;
        }

        if packet.delete_new_key {
            self.keys.remove(&packet.new_key_id);
            if self.session_key_id == Some(packet.new_key_id) {
                self.session_key_id = None;
            }
            #[cfg(feature = "debug")]
            {
                println!(
                    "GROUP : User {} deleted key {}",
                    self.user_id, packet.new_key_id
                );
            }
        } else {
            self.keys.insert(packet.new_key_id, packet.new_key);
            if packet.is_session_key {
                self.session_key_id = Some(packet.new_key_id);
            }
            #[cfg(feature = "debug")]
            {
                println!(
                    "GROUP : User {} updated key {} with new key {}",
                    self.user_id, packet.new_key_id, packet.new_key_id
                );
            }
        }
    }
}

struct TreeTestUser {
    users: Vec<TestUser>,
}

impl fmt::Debug for TreeTestUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TreeTestUser : ").ok();
        for user in self.users.iter() {
            write!(f, "\n\t{:?}", user).ok();
        }
        Ok(())
    }
}

impl TreeTestUser {
    fn get_user(&mut self, id: usize) -> Option<&mut TestUser> {
        self.users.get_mut(id)
    }
    fn get_user_by_id(&mut self, user_id: &str) -> Option<usize> {
        self.users.iter().position(|u| u.user_id == user_id)
    }
    fn check_session_key(&self, session_key_id: u64) -> bool {
        self.users.iter().any(|u| {
            if u.in_tree && u.session_key_id == Some(session_key_id) {
                true
            } else {
                !u.in_tree && u.session_key_id != Some(session_key_id)
            }
        })
    }
    fn print_users_in_tree(&self) {
        let ids: Vec<String> = self
            .users
            .iter()
            .filter(|u| u.in_tree)
            .map(|u| u.user_id.clone())
            .collect();
        println!("Users in tree : {:?}", ids,);
    }
    fn new_user(&mut self) -> usize {
        let user_id = format!("User{}", self.users.len());
        let keys = HashMap::new();
        let test_user = TestUser {
            user_id,
            keys,
            key_len: 32,
            session_key_id: None,
            in_tree: false,
        };
        self.users.push(test_user);
        self.users.len() - 1
    }
    fn receive_group(&mut self, wrapped: WrappedKeyUpdatePacket) {
        #[cfg(feature = "debug")]
        {
            println!("received group data : {:x?}", data);
        }
        for i in self.users.iter_mut() {
            i.receive_group(wrapped.clone());
        }
    }
    fn add_user_to_tree(&mut self, id: usize) {
        self.users.get_mut(id).expect("Invalid user id").in_tree = true;
    }
    fn add_users_to_tree(&mut self, ids: Vec<usize>) {
        for id in ids {
            self.add_user_to_tree(id);
        }
    }
    fn remove_user_from_tree(&mut self, id: usize) {
        self.users.get_mut(id).expect("Invalid user id").in_tree = false;
    }
}

fn verify_key_chain(tree: &Lkh, users: &TreeTestUser) -> bool {
    for user in users.users.iter() {
        let user_id = user.user_id.clone();
        let keys = &user.keys;
        let mut key_count = 0;
        let mut node_id = tree.tree.get_user_node(&user_id).copied();

        loop {
            if node_id.is_none() {
                break;
            }
            let id = node_id.unwrap();
            let node = tree.tree.get_node_by_id(id);
            if node.is_none() {
                println!("Cannot find node using this id {}", id);
                return false;
            }
            let node = node.unwrap();
            let key = &node.key;
            let key_id = &node.key_id;
            if !(keys.contains_key(key_id) && keys[key_id] == *key) {
                return false;
            }
            key_count += 1;
            node_id = tree.tree.get_parent(id).as_ref().map(|u| u.id);
        }
        if key_count > keys.len() {
            //If a key is repeated multiple time in the path to root
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {

    use std::{cell::RefCell, rc::Rc, sync::Mutex};

    //use rand::{RngExt, SeedableRng};

    use super::*;
    #[test]
    fn test_create() {
        let tree = Tree::new();
        let lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(|data| println!("Sending group data: {:?}", data)),
            
        };
        println!("{:?}", lkh);
    }

    #[test]
    fn test_update_on_already_updated_node() {
        let tree = Tree::new();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(|data| println!("recieved group data: {:x?}", data)),
            
        };
        println!("{:?}", lkh);

        lkh.add_user(
            "User0".to_string(),
            Box::new(|data| println!("Recieved privately : {:x?}", data)),
        );
        println!("{:?}", lkh);
        let key = lkh.tree.get_node_by_id(1).unwrap().key.clone();

        let mut already_updated = HashSet::from([1 as usize]);
        lkh.update_keys(1, &mut already_updated);
        let after_key = lkh.tree.get_node_by_id(1).unwrap().key.clone();
        assert_eq!(key, after_key)
    }
    #[test]
    fn test_add_one_user() {
        let tree = Tree::new();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(|data| println!("recieved group data: {:x?}", data)),
            
        };
        println!("{:?}", lkh);

        lkh.add_user(
            "User0".to_string(),
            Box::new(|data| println!("Recieved privately : {:x?}", data)),
        );
        println!("{:?}", lkh);
    }
    #[test]
    fn test_add_three_user() {
        let tree = Tree::new();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(|data| println!("Sending group data: {:?}", data)),
            
        };
        println!("{:?}", lkh);

        lkh.add_user(
            "User0".to_string(),
            Box::new(|data| println!("0 Recieved privately : {:?}", data)),
        );
        println!("{:?}", lkh);
        lkh.add_user(
            "User1".to_string(),
            Box::new(|data| println!("1 Recieved privately : {:?}", data)),
        );
        println!("{:?}", lkh);
        lkh.add_user(
            "User2".to_string(),
            Box::new(|data| println!("2 Recieved privately : {:?}", data)),
        );
        println!("{:?}", lkh);
    }
    #[test]
    fn test_adding_one_user_realist() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };

        let user_id = users.lock().unwrap().new_user();
        let unicast_user = users.clone();
        let unicast_user_id = unicast_user
            .lock().unwrap()
            .get_user(user_id)
            .expect("invalid id")
            .user_id
            .clone();
        users.lock().unwrap().add_user_to_tree(user_id);
        lkh.add_user(
            unicast_user_id,
            Box::new(move |data| {
                unicast_user
                    .lock().unwrap()
                    .get_user(user_id)
                    .expect("invalid id")
                    .receive_single(data)
            }),
        );

        println!("{:?}", lkh);
        println!("{:?}", users);
        assert!(verify_key_chain(&lkh, &*users.lock().unwrap()));
    }
    #[test]
    fn test_adding_three_user_realist() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        for _ in 0..3 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.lock().unwrap().add_user_to_tree(user_id);
            lkh.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .lock().unwrap()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
            let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
            assert!(users.lock().unwrap().check_session_key(rootkeyid));
            println!("{:?}", lkh);
            println!("{:?}", users);
        }

        let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
        assert!(users.lock().unwrap().check_session_key(rootkeyid));
        assert!(verify_key_chain(&lkh, &*users.lock().unwrap()));
    }

    #[test]
    fn test_adding_32_user_realist() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        for _ in 0..32 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.lock().unwrap().add_user_to_tree(user_id);
            lkh.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .lock().unwrap()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
            let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
            assert!(users.lock().unwrap().check_session_key(rootkeyid));
            println!("{:?}", lkh);
        }
        println!("{:?}", users);
        let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
        assert!(users.lock().unwrap().check_session_key(rootkeyid));
        assert!(verify_key_chain(&lkh, &*users.lock().unwrap()));

        lkh.tree.to_dot();
    }

    #[test]
    fn test_remove_user() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        for _ in 0..3 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.lock().unwrap().add_user_to_tree(user_id);
            lkh.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .lock().unwrap()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
        }
        println!("{:?}", lkh);
        println!("{:?}", users);
        lkh.remove_user(&"User1".to_string());
        let user_id = users
            .lock().unwrap()
            .get_user_by_id(&"User1".to_string())
            .unwrap();
        users.lock().unwrap().remove_user_from_tree(user_id);
        println!("After removing User1");
        println!("{:?}", lkh);
        println!("{:?}", users);
        let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
        assert!(users.lock().unwrap().check_session_key(rootkeyid));
        assert!(verify_key_chain(&lkh, &*users.lock().unwrap()));
    }

    #[test]
    fn test_remove_all_user() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        for _ in 0..3 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.lock().unwrap().add_user_to_tree(user_id);
            lkh.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .lock().unwrap()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
            let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
            assert!(users.lock().unwrap().check_session_key(rootkeyid));
            assert!(verify_key_chain(&lkh, &*users.lock().unwrap()));
        }
        println!("{:?}", lkh);
        println!("{:?}", users);
        for i in 0..3 {
            lkh.remove_user(&format!("User{}", i));
            let user_id = users
                .lock().unwrap()
                .get_user_by_id(&format!("User{}", i))
                .unwrap();
            users.lock().unwrap().remove_user_from_tree(user_id);
            if lkh.get_user_count() > 0 {
                println!("Users count : {}", lkh.get_user_count());
                let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
                assert!(users.lock().unwrap().check_session_key(rootkeyid));
            }
        }
        assert!(verify_key_chain(&lkh, &*users.lock().unwrap()));
        println!("After removing all users");
        println!("{:?}", lkh);
        println!("{:?}", users);
    }
    /*#[test]
    fn random_test() {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let n = 32;
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        for _ in 0..n {
            users.lock().unwrap().new_user();
        }
        //let mut actions = Vec::new();
        for i in 0..100000 {
            if (i % 1000 == 0) {
                //println!("{}", i);
                //users.borrow().print_users_in_tree();
            }

            //println!("Actions : {:?}", actions);
            let user_id = rng.random_range(0..n) as usize;
            let user_in_vec = users
                .lock().unwrap()
                .get_user_by_id(&format!("User{}", user_id).to_string())
                .expect("User unexpectedly not in array");
            let in_tree = users
                .lock().unwrap()
                .get_user(user_in_vec)
                .expect("Unexpectedly not in array")
                .in_tree
                .clone();
            //println!("{:?}", lkh.tree.depth);
            //println!("{}", lkh.tree);

            if !in_tree {
                //Add user
                //println!("Adding User{}", user_id);
                //actions.push(format!("Adding User{}", user_id));
                let unicast_user = users.clone();
                let unicast_user_id = unicast_user
                    .lock().unwrap()
                    .get_user(user_id)
                    .expect("invalid id")
                    .user_id
                    .clone();
                users.lock().unwrap().add_user_to_tree(user_id);
                lkh.add_user(
                    unicast_user_id,
                    Box::new(move |data| {
                        unicast_user
                            .lock().unwrap()
                            .get_user(user_id)
                            .expect("invalid id")
                            .receive_single(data)
                    }),
                );
            } else {
                //println!("Removing User{}", user_id);

                //actions.push(format!("Removing User{}", user_id));
                //Remove user
                lkh.remove_user(&format!("User{}", user_id));
                users.lock().unwrap().remove_user_from_tree(user_id);
            }
            users.lock().unwrap().print_users_in_tree();
            if !(lkh.tree.verify_integrity() && verify_key_chain(&lkh, &*users.lock().unwrap())) {
                println!("{:?}", lkh.tree.depth);
                println!("{}", lkh.tree);

                panic!();
            }
        }
    }*/
    /*#[test]
    fn random_test_speed() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let n = 32;
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        for _ in 0..n {
            users.lock().unwrap().new_user();
        }

        for i in 0..100000 {
            if (i % 1000 == 0) {
                println!("{}", i);
            }
            let user_id = (rand::random::<u64>() % n) as usize;
            let user_in_vec = users
                .lock().unwrap()
                .get_user_by_id(&format!("User{}", user_id).to_string())
                .expect("User unexpectedly not in array");
            let in_tree = users
                .lock().unwrap()
                .get_user(user_in_vec)
                .expect("Unexpectedly not in array")
                .in_tree
                .clone();

            if !in_tree {
                //Add user

                let unicast_user = users.clone();
                let unicast_user_id = unicast_user
                    .lock().unwrap()
                    .get_user(user_id)
                    .expect("invalid id")
                    .user_id
                    .clone();
                users.lock().unwrap().add_user_to_tree(user_id);
                lkh.add_user(
                    unicast_user_id,
                    Box::new(move |data| {
                        unicast_user
                            .lock().unwrap()
                            .get_user(user_id)
                            .expect("invalid id")
                            .receive_single(data)
                    }),
                );
            } else {
                //Remove user
                lkh.remove_user(&format!("User{}", user_id));
                users.lock().unwrap().remove_user_from_tree(user_id);
            }
        }
    }*/

    #[test]
    fn add_simple_group() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        let mut users_vec = Vec::new();
        let mut user_id_vec = Vec::new();
        for _ in 0..4 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            let func = Box::new(move |data| {
                unicast_user
                    .lock().unwrap()
                    .get_user(user_id)
                    .expect("invalid id")
                    .receive_single(data)
            });
            let user = User {
                user_id: unicast_user_id,
                send: func,
            };
            user_id_vec.push(user_id);
            users_vec.push(user);
        }

        lkh.add_user_vec(users_vec);
        users.lock().unwrap().add_users_to_tree(user_id_vec);
        println!("{:?}", lkh);
        println!("{:?}", users);

        let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
        assert!(users.lock().unwrap().check_session_key(rootkeyid));
        assert!(verify_key_chain(&lkh, &*users.lock().unwrap()));
        assert!(lkh.tree.verify_integrity());
    }
    #[test]
    fn add_successive_group() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        let mut users_vec = Vec::new();
        let mut user_id_vec = Vec::new();
        for _ in 0..4 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            let func = Box::new(move |data| {
                unicast_user
                    .lock().unwrap()
                    .get_user(user_id)
                    .expect("invalid id")
                    .receive_single(data)
            });
            let user = User {
                user_id: unicast_user_id,
                send: func,
            };
            user_id_vec.push(user_id);
            users_vec.push(user);
        }

        lkh.add_user_vec(users_vec);
        users.lock().unwrap().add_users_to_tree(user_id_vec);
        println!("{:?}", lkh);
        println!("{:?}", users);

        let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
        assert!(users.lock().unwrap().check_session_key(rootkeyid));
        assert!(verify_key_chain(&lkh, &*users.lock().unwrap()));
        assert!(lkh.tree.verify_integrity());

        let mut users_vec = Vec::new();
        let mut user_id_vec = Vec::new();
        for _ in 0..15 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            let func = Box::new(move |data| {
                unicast_user
                    .lock().unwrap()
                    .get_user(user_id)
                    .expect("invalid id")
                    .receive_single(data)
            });
            let user = User {
                user_id: unicast_user_id,
                send: func,
            };
            user_id_vec.push(user_id);
            users_vec.push(user);
        }
        lkh.add_user_vec(users_vec);
        users.lock().unwrap().add_users_to_tree(user_id_vec);
        println!("{:?}", lkh);
        println!("{:?}", users);

        let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
        assert!(users.lock().unwrap().check_session_key(rootkeyid));
        assert!(verify_key_chain(&lkh, &*users.lock().unwrap()));
        assert!(lkh.tree.verify_integrity());
    }

    #[test]
    fn test_adding_one_user_realist_lkhplus() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        let mut lkhp = LKHPlus {
            unordered_users: HashMap::new(),
            max_unordered_count: 32,

            lkh: lkh,
        };

        let user_id = users.lock().unwrap().new_user();
        let unicast_user = users.clone();
        let unicast_user_id = unicast_user
            .lock().unwrap()
            .get_user(user_id)
            .expect("invalid id")
            .user_id
            .clone();
        users.lock().unwrap().add_user_to_tree(user_id);
        lkhp.add_user(
            unicast_user_id,
            Box::new(move |data| {
                unicast_user
                    .lock().unwrap()
                    .get_user(user_id)
                    .expect("invalid id")
                    .receive_single(data)
            }),
        );

        println!("{:?}", lkhp);
        println!("{:?}", users);
        assert!(verify_key_chain(&lkhp.lkh, &*users.lock().unwrap()));
    }
    #[test]
    fn test_adding_three_user_realist_lkhplus() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        let mut lkhp = LKHPlus {
            unordered_users: HashMap::new(),
            max_unordered_count: 32,

            lkh: lkh,
        };
        for _ in 0..3 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.lock().unwrap().add_user_to_tree(user_id);
            lkhp.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .lock().unwrap()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
            let rootkeyid = lkhp.get_session_key().expect("No session key").0;
            assert!(users.lock().unwrap().check_session_key(rootkeyid));
            println!("{:?}", lkhp);
            println!("{:?}", users);
        }

        let rootkeyid = lkhp.get_session_key().expect("No session key").0;
        assert!(users.lock().unwrap().check_session_key(rootkeyid));
        assert!(verify_key_chain(&lkhp.lkh, &*users.lock().unwrap()));
    }

    #[test]
    fn test_adding_32_user_realist_lkhplus() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        let mut lkhp = LKHPlus {
            unordered_users: HashMap::new(),
            max_unordered_count: 32,

            lkh: lkh,
        };
        for _ in 0..32 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.lock().unwrap().add_user_to_tree(user_id);
            lkhp.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .lock().unwrap()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
            let rootkeyid = lkhp.get_session_key().expect("No session key").0;
            assert!(users.lock().unwrap().check_session_key(rootkeyid));
            println!("{:?}", lkhp);
        }
        println!("{:?}", users);
        let rootkeyid = lkhp.get_session_key().expect("No session key").0;
        assert!(users.lock().unwrap().check_session_key(rootkeyid));
        assert!(verify_key_chain(&lkhp.lkh, &*users.lock().unwrap()));

        lkhp.lkh.tree.to_dot();
    }
    #[test]
    fn test_remove_user_lkhplus() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        let mut lkhp = LKHPlus {
            unordered_users: HashMap::new(),
            max_unordered_count: 32,

            lkh: lkh,
        };
        for _ in 0..3 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.lock().unwrap().add_user_to_tree(user_id);
            lkhp.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .lock().unwrap()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
        }
        println!("{:?}", lkhp);
        println!("{:?}", users);
        lkhp.remove_user(&"User1".to_string());
        let user_id = users
            .lock().unwrap()
            .get_user_by_id(&"User1".to_string())
            .unwrap();
        users.lock().unwrap().remove_user_from_tree(user_id);
        println!("After removing User1");
        println!("{}", lkhp);
        println!("{:?}", users);
        let rootkeyid = lkhp.get_session_key().expect("No session key").0;
        assert!(users.lock().unwrap().check_session_key(rootkeyid));
        assert!(verify_key_chain(&lkhp.lkh, &*users.lock().unwrap()));
    }

    #[test]
    fn test_remove_all_user_lkhplus() {
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        let mut lkhp = LKHPlus {
            unordered_users: HashMap::new(),
            max_unordered_count: 32,

            lkh: lkh,
        };
        for _ in 0..32 {
            let user_id = users.lock().unwrap().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .lock().unwrap()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.lock().unwrap().add_user_to_tree(user_id);
            lkhp.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .lock().unwrap()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
            let rootkeyid = lkhp.get_session_key().expect("No session key").0;
            assert!(users.lock().unwrap().check_session_key(rootkeyid));
            assert!(verify_key_chain(&lkhp.lkh, &*users.lock().unwrap()));
        }
        println!("{:?}", lkhp);
        println!("{:?}", users);
        for i in 0..32 {
            lkhp.remove_user(&format!("User{}", i));
            let user_id = users
                .lock().unwrap()
                .get_user_by_id(&format!("User{}", i))
                .unwrap();
            users.lock().unwrap().remove_user_from_tree(user_id);
            if lkhp.lkh.get_user_count() > 0 {
                println!("Users count : {}", lkhp.lkh.get_user_count());
                let rootkeyid = lkhp.get_session_key().expect("No session key").0;
                assert!(users.lock().unwrap().check_session_key(rootkeyid));
            }
        }
        assert!(verify_key_chain(&lkhp.lkh, &*users.lock().unwrap()));
        println!("After removing all users");
        println!("{:?}", lkhp);
        println!("{:?}", users);
    }
    /*#[test]
    fn random_test_lkhplus() {
        let mut rng = rand::rngs::SmallRng::seed_from_u64(1);
        let tree = Tree::new();
        let users = Arc::new(Mutex::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let n = 32;
        let mut lkh = Lkh {
            tree: tree,
            key_size: 32,
            send_group: Box::new(move |data| users_lkh.lock().unwrap().receive_group(data)),
            
        };
        let mut lkhp = LKHPlus {
            unordered_users: HashMap::new(),
            max_unordered_count: 32,

            lkh: lkh,
        };
        for _ in 0..n {
            users.lock().unwrap().new_user();
        }
        //let mut actions = Vec::new();
        for i in 0..100000 {
            if (i % 1000 == 0) {
                //println!("{}", i);
                //users.borrow().print_users_in_tree();
            }

            //println!("Actions : {:?}", actions);
            let user_id = rng.random_range(0..n) as usize;
            let user_in_vec = users
                .lock().unwrap()
                .get_user_by_id(&format!("User{}", user_id).to_string())
                .expect("User unexpectedly not in array");
            let in_tree = users
                .lock().unwrap()
                .get_user(user_in_vec)
                .expect("Unexpectedly not in array")
                .in_tree
                .clone();
            //println!("{:?}", lkh.tree.depth);
            //println!("{}", lkh.tree);

            if !in_tree {
                //Add user
                //println!("Adding User{}", user_id);
                //actions.push(format!("Adding User{}", user_id));
                let unicast_user = users.clone();
                let unicast_user_id = unicast_user
                    .lock().unwrap()
                    .get_user(user_id)
                    .expect("invalid id")
                    .user_id
                    .clone();
                users.lock().unwrap().add_user_to_tree(user_id);
                lkhp.add_user(
                    unicast_user_id,
                    Box::new(move |data| {
                        unicast_user
                            .lock().unwrap()
                            .get_user(user_id)
                            .expect("invalid id")
                            .receive_single(data)
                    }),
                );
            } else {
                //println!("Removing User{}", user_id);

                //actions.push(format!("Removing User{}", user_id));
                //Remove user
                lkhp.remove_user(&format!("User{}", user_id));
                users.lock().unwrap().remove_user_from_tree(user_id);
            }
            users.lock().unwrap().print_users_in_tree();
            if !(lkhp.lkh.tree.verify_integrity() && verify_key_chain(&lkhp.lkh, &*users.lock().unwrap()))
            {
                println!("{:?}", lkhp.lkh.tree.depth);
                println!("{}", lkhp.lkh.tree);

                panic!();
            }
        }
    }*/
}
