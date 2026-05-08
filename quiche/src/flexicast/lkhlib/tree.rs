use crate::flexicast::lkhlib::node::Node;
use crate::flexicast::lkhlib::user::User;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;

pub trait BinaryTree {
    type Node;
    /// Ownership of right_node will be transfered to the tree
    /// Return the node_id of the new node
    fn add_node(&mut self, node: Node) -> usize;
    /// delete node_id_to_delete and merge it's brother in the parent,
    /// return the id of the new merged node
    /// If node_id_to_delete is root, the tree will be emptied and 0 will be returned
    fn merge_nodes(&mut self, node_id_to_delete: usize) -> usize;
    /// Get the right child of a node, if it exists
    fn get_right_child(&self, node_id: usize) -> &Option<Node>;
    /// Get the left child of a node, if it exists
    fn get_left_child(&self, node_id: usize) -> &Option<Node>;
    /// Get the parent of a node, if it exists
    fn get_parent(&self, node_id: usize) -> &Option<Node>;
    // get a mutable reference to a node by its id, if it exists
    fn get_node_by_id_mut(&mut self, node_id: usize) -> Option<&mut Node>;
    fn get_node_by_id(&self, node_id: usize) -> Option<&Node>;
    fn get_root(&self) -> Option<&Node>;
    fn get_user_node(&self, user_id: &str) -> Option<&usize>;
    fn get_user_count(&self) -> usize;
    fn verify_integrity(&self) -> bool;
}
#[derive(Debug)]
#[derive(Default)]
pub struct Tree {
    //root: Option<Node>,
    //nodes: HashMap<u64, &'a Node>, //Association between nodeID and node
    pub depth: HashMap<u64, BTreeSet<usize>>, //Association between depth (0 being root) and the set of leaves at that depth
    users: HashMap<String, usize>, //Association between userID and node, not ideal, should be in LKH
    array: Vec<Option<Node>>,
}
//Gemini
impl fmt::Display for Tree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Check if the array is empty or the root is None
        if self.array.is_empty() || self.array[0].is_none() {
            return writeln!(f, "Empty Tree");
        }

        writeln!(f, "Binary Tree:")?;

        // Start recursion from the root (ID 1, Index 0)
        self.format_node(f, 1, 0)
    }
}


impl Tree {
    pub fn new() -> Self {
        Tree {
            users: HashMap::new(),
            array: Vec::new(),
            depth: HashMap::new(),
        }
    }
    // Helper function to handle indentation and child lookups
    fn format_node(&self, f: &mut fmt::Formatter, id: u64, indent: usize) -> fmt::Result {
        let index = (id - 1) as usize;

        // 1. Try to get the node at the current index
        match self.array.get(index).and_then(|slot| slot.as_ref()) {
            Some(node) => {
                // 2. Print the current node with indentation
                writeln!(
                    f,
                    "{:indent$}- [ID: {}] {}",
                    "",
                    id,
                    node,
                    indent = indent * 4
                )?;

                // 3. Calculate child IDs
                let left_id = 2 * id;
                let right_id = 2 * id + 1;

                // 4. Recurse to children if they exist in the array bounds
                // We only recurse if the index is within the array to avoid infinite loops
                if (left_id as usize) <= self.array.len() {
                    self.format_node(f, left_id, indent + 1)?;
                }
                if (right_id as usize) <= self.array.len() {
                    self.format_node(f, right_id, indent + 1)?;
                }
                Ok(())
            }
            // If the slot is None, we just don't print anything for this branch
            None => Ok(()),
        }
    }
    //gemini
    pub fn to_dot(&self) {
        println!("digraph BinaryTree {{");
        println!("  node [fontname=\"Arial\"];");

        for (i, val) in self.array.iter().enumerate() {
            if val.is_some() {
                let id = i + 1; // 1-based logic as per your description
                let left = 2 * id;
                let right = 2 * id + 1;

                // Draw the current node
                println!(
                    "  {} [label=\"ID: {}\\n{}\"];",
                    id,
                    id,
                    val.as_ref().unwrap()
                );

                // Link to left child (if it exists in the array)
                if left <= self.array.len() {
                    println!("  {} -> {} [label=\"L\"];", id, left);
                }

                // Link to right child (if it exists in the array)
                if right <= self.array.len() {
                    println!("  {} -> {} [label=\"R\"];", id, right);
                }
            }
        }

        println!("}}");
    }

    fn update_children(&mut self, old_node_id: usize, new_node_id: usize) {
        //We suppose that the current node is correct, we may need to update it's children

        //let direction = old_node_id % 2;
        let mut queue = VecDeque::new();

        queue.push_back((old_node_id, new_node_id));

        while !queue.is_empty() {
            let (old_node_id, new_node_id) = queue.pop_front().unwrap();
            if self.array.len() >= 2 * old_node_id {
                let parent_depth = self.array[new_node_id - 1]
                    .as_ref()
                    .expect("Invalid node update")
                    .depth;

                //left

                match self.array[2 * old_node_id - 1] {
                    None => {}
                    _ => {
                        let mut node = self.array[2 * old_node_id - 1]
                            .take()
                            .expect("Unexpected none");

                        let old_id = node.id;
                        let new_id = 2 * new_node_id;
                        let old_depth = node.depth;
                        node.id = new_id;
                        node.depth = parent_depth + 1;
                        match node.user.as_ref() {
                            None => {}
                            Some(user) => {
                                self.depth
                                    .get_mut(&old_depth)
                                    .expect("Old depth not found")
                                    .remove(&old_id);
                                self.depth.entry(node.depth).or_default().insert(node.id);
                                self.users.insert(user.user_id.clone(), node.id);
                                /*println!(
                                    "moving up {} from {} to {}",
                                    user.user_id, old_depth, node.depth
                                ); */
                            }
                        }

                        self.array[new_id - 1] = Some(node);
                        queue.push_back((old_id, new_id));
                    }
                }
                //right
                match self.array[2 * old_node_id] {
                    None => {}
                    _ => {
                        let mut node = self.array[2 * old_node_id].take().expect("Unexpected none");

                        let old_id = node.id;
                        let new_id = 2 * new_node_id + 1;
                        let old_depth = node.depth;

                        node.id = new_id;
                        node.depth = parent_depth + 1;

                        match node.user.as_ref() {
                            None => {}
                            Some(user) => {
                                self.users.insert(user.user_id.clone(), node.id);
                                self.depth
                                    .get_mut(&old_depth)
                                    .expect("Old depth not found")
                                    .remove(&old_id);
                                self.depth.entry(node.depth).or_default().insert(node.id);
                                /*println!(
                                    "moving up {} from {} to {}",
                                    user.user_id, old_depth, node.depth
                                );*/
                            }
                        }

                        self.array[new_id - 1] = Some(node);
                        queue.push_back((old_id, new_id));
                    }
                }
            }
        }
    }
}
impl BinaryTree for Tree {
    type Node = Node;

    fn get_user_count(&self) -> usize {
        self.users.len()
    }
    fn verify_integrity(&self) -> bool {
        for (depth, node_ids) in &self.depth {
            for node_id in node_ids {
                if let Some(node) = self.array[node_id - 1].as_ref() {
                    if node.depth != *depth {
                        println!(
                            "Integrity error: Node ID {} has depth {}, expected {}",
                            node_id, node.depth, depth
                        );
                        return false;
                    }
                    if node.user.is_none() {
                        println!("Integrity error: Node ID {} has no user", node_id);
                        return false;
                    }
                    if *node_id > 1
                        && (self.array.len() < (node_id ^ 1)
                            || self.array[(node_id ^ 1) - 1].is_none())
                    {
                        println!(
                            "Integrity error: Node ID {} is a leaf but has no brother",
                            node_id
                        );
                        return false;
                    }
                } else {
                    println!("Integrity error: Node ID {} not found in array", node_id);
                    return false;
                }
            }
        }

        true
    }
    fn add_node(&mut self, mut right_node: Node) -> usize {
        let min_depth = self
            .depth
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, _)| k)
            .min()
            .copied(); //Get _a_ leaf with the smallest depth
        match min_depth {
            Some(target_depth) => {
                let target_depth_set = self
                    .depth
                    .get_mut(&target_depth)
                    .expect("Target depth unavailable");
                let target_node_id = *target_depth_set
                    .iter()
                    .next()
                    .expect("Depth unexpectedly empty");

                target_depth_set.take(&target_node_id);

                if self.array.len() < (2 * target_node_id + 1) {
                    self.array.resize(2 * target_node_id + 1, None);
                }

                let target_node = self
                    .array
                    .get_mut(target_node_id - 1)
                    .expect("unallowed access")
                    .as_mut()
                    .expect("Node in self.depth not in array");

                let mut left_node = target_node.clone();
                target_node.user = None;
                right_node.id = 2 * target_node_id + 1;
                left_node.id = 2 * target_node_id;
                left_node.depth = target_node.depth + 1;
                right_node.depth = target_node.depth + 1;

                let new_depth = self.depth.get_mut(&(target_depth + 1));
                match &left_node.user {
                    None => {}
                    Some(user) => {
                        self.users.insert(user.user_id.clone(), left_node.id);
                    }
                }
                match &right_node.user {
                    None => {}
                    Some(user) => {
                        self.users.insert(user.user_id.clone(), right_node.id);
                    }
                }

                match new_depth {
                    None => {
                        //let depth_set = vec![left_node.id, right_node.id];
                        let depth_set = BTreeSet::from([left_node.id, right_node.id]);
                        self.depth.insert(target_depth + 1, depth_set);
                    }
                    Some(depth_set) => {
                        depth_set.insert(left_node.id);
                        depth_set.insert(right_node.id);
                    }
                }
                let l_id = left_node.id - 1;
                let r_id = right_node.id - 1;

                self.array[l_id] = Some(left_node);
                self.array[r_id] = Some(right_node);

                r_id + 1
            }
            None => {
                //In this case, the tree is empty
                right_node.id = 1;
                right_node.depth = 0;
                println!("No min depth found, adding node as root");
                //self.depth.insert(0, vec![1]);
                match right_node.user.as_ref() {
                    None => {}
                    Some(user) => {
                        self.users.insert(user.user_id.clone(), 1);
                    }
                }   
                

                self.array.resize(1, None);
                self.array[0] = Some(right_node);
                self.depth.insert(0, BTreeSet::from([1]));
                1
            }
        }
    }

    fn merge_nodes(&mut self, node_id_to_delete: usize) -> usize {
        // Objective : delete node_to_delete and merge it's brother in the parent

        if node_id_to_delete <= 1 {
            //Then node_to_delete is root
            self.users.clear();
            self.array.drain(..);
            self.depth.drain();
            return 0;
        }
        if node_id_to_delete > self.array.len() {
            return 0;
        }

        let node_to_delete = self.array[node_id_to_delete - 1]
            .take()
            .expect("Trying to delete non-existing node");
        let mut brother = self.array[(node_id_to_delete ^ 1) - 1]
            .take()
            .expect("Not root and no brother");
        let parent = self
            .array
            .get_mut(node_id_to_delete / 2 - 1)
            .expect("Invalid Parent ID")
            .as_mut()
            .expect("Orphaned node trying to merge");
        let old_depth = self
            .depth
            .get_mut(&node_to_delete.depth)
            .expect("Merged node is not a leaf");
        if old_depth.contains(&brother.id) {
            old_depth.remove(&brother.id);
        }

        old_depth.remove(&node_to_delete.id);

        //Still need to update the childrens of brother to reflect the correct depth
        let old_id = brother.id;
        let new_id = parent.id;
        brother.id = new_id;
        match &node_to_delete.user {
            None => {}
            Some(user) => {
                self.users.remove(user.user_id.as_str());
            }
        }
        match &brother.user {
            None => {}
            Some(user) => {
                self.users.insert(user.user_id.clone(), brother.id);
            }
        }
        let old_depth = brother.depth;
        brother.depth = parent.depth;

        if brother.user.is_some() {
            self.depth
                .get_mut(&old_depth)
                .expect("Old depth not found")
                .remove(&old_id);
            self.depth.entry(brother.depth).or_default().insert(new_id);
        }

        self.array[new_id - 1] = Some(brother);

        self.update_children(old_id, new_id);
        new_id
    }

    fn get_node_by_id_mut(&mut self, node_id: usize) -> Option<&mut Node> {
        if (node_id) > self.array.len() {
            return None;
        }

        //return self.array[(node_id - 1) as usize];
        self.array
            .get_mut(node_id - 1)
            .expect("Unexpected id miss")
            .as_mut()
    }
    fn get_node_by_id(&self, node_id: usize) -> Option<&Node> {
        if (node_id - 1) > self.array.len() {
            return None;
        }

        //return self.array[(node_id - 1) as usize];
        self.array[node_id - 1].as_ref()
    }
    fn get_left_child(&self, node_id: usize) -> &Option<Node> {
        if self.array.len() >= 2 * node_id {
            &self.array[2 * node_id - 1]
        } else {
            &None
        }
    }

    fn get_right_child(&self, node_id: usize) -> &Option<Node> {
        if self.array.len() > 2 * node_id {
            &self.array[2 * node_id]
        } else {
            &None
        }
    }

    fn get_parent(&self, node_id: usize) -> &Option<Node> {
        // Implementation to get the parent of a node
        if node_id <= 1 {
            &None
        } else if self.array.len() >= node_id / 2 {
            &self.array[node_id / 2 - 1]
        } else {
            &None
        }
    }
    fn get_root(&self) -> Option<&Node> {
        if self.array.is_empty() {
            return None;
        }
        match &self.array[0] {
            Some(node) => Some(node),
            None => None,
        }
    }

    fn get_user_node(&self, user_id: &str) -> Option<&usize> {
        self.users.get(user_id)
    }
}

#[cfg(test)]
mod tests {
    

    use super::*;

    #[test]
    fn test_creation() {
        let mut a = Tree::new();
        println!("{:?}", a.get_root());
        let node = Node {
            depth: 0,
            id: 5,
            key: vec![0; 8],
            key_id: 0,
            user: None,
        };
        a.add_node(node);
        println!("{}", a);
        let node2 = Node {
            depth: 0,
            id: 5,
            key: vec![1; 8],
            key_id: 1,
            user: None,
        };
        a.add_node(node2);
        println!("{}", a);
        a.to_dot();
    }

    #[test]
    fn test_medium_tree() {
        let mut a = Tree::new();
        for i in 1..16 {
            let node = Node {
                depth: 0,
                id: 5,
                key: vec![1; 8],
                key_id: i,
                user: None,
            };
            a.add_node(node);
            print!("{}", a);
            a.to_dot();
        }
    }
    #[test]
    fn test_destroy_root() {
        let mut a = Tree::new();
        let node = Node {
            depth: 0,
            id: 5,
            key: vec![1; 8],
            key_id: 0,
            user: None,
        };

        let id = a.add_node(node);
        println!("{}", a);
        a.merge_nodes(id);
        println!("{}", a);
    }

    #[test]
    fn test_remove_one_node() {
        let mut a = Tree::new();

        let node = Node {
            depth: 0,
            id: 5,
            key: vec![1; 8],
            key_id: 0,
            user: None,
        };

        let mut index = a.add_node(node);
        println!("{}", a);
        a.merge_nodes(index);
        println!("{}", a);
        for i in 1..4 {
            let node = Node {
                depth: 0,
                id: 5,
                key: vec![i; 8],
                key_id: i as u64,
                user: None,
            };
            index = a.add_node(node);
            println!("Adding {} :\n {}", index, a)
        }
        println!("Before removal of {}:\n{}", index, a);
        a.merge_nodes(index - 1);
        println!("After Removal :\n{}", a);
    }

    #[test]
    fn test_add_then_delete() {
        let mut a = Tree::new();

        for i in 0..32 {
            let node = Node {
                depth: 0,
                id: 5,
                key: vec![1; 8],
                key_id: i,
                user: None,
            };
            a.add_node(node);
        }
        loop {
            let max_depth = a
                .depth
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, _)| k)
                .max()
                .copied();
            match max_depth {
                None => break,
                Some(max_depth) => {
                    let target_depth_set = a
                        .depth
                        .get_mut(&max_depth)
                        .expect("Target depth unavailable");
                    let target_node_id = *target_depth_set
                        .iter()
                        .next()
                        .expect("Depth unexpectedly empty");
                    a.merge_nodes(target_node_id);
                    println!("Removing {}:\n{}", target_node_id, a)
                }
            }
        }
    }

    #[test]
    fn test_with_users() {
        let mut a = Tree::new();

        for i in 0..4 {
            let user = User {
                user_id: format!("user{}", i),
                send: Box::new(|data| ()),
            };
            let node = Node {
                depth: 0,
                id: 5,
                key: vec![1; 8],
                key_id: i,
                user: Some(std::rc::Rc::new(user)),
            };
            a.add_node(node);
            println!("{}", a);
        }
    }

    #[test]
    fn test_move_up_subtree() {
        let mut a = Tree::new();

        for i in 0..4 {
            let user = User {
                user_id: format!("user{}", i),
                send: Box::new(|data| ()),
            };
            let node = Node {
                depth: 0,
                id: 5,
                key: vec![1; 8],
                key_id: i,
                user: Some(std::rc::Rc::new(user)),
            };
            a.add_node(node);
        }
        println!("Before moving up:\n{}", a);
        a.merge_nodes(4);
        println!("Mid step:\n{}", a);
        a.merge_nodes(2);
        println!("After moving up:\n{}", a);
    }
}
