//! Asynchronous control loop between flexicast source and unicast server with
//! tokio.

use quiche::multicast::McAnnounceData;
use tokio::sync::mpsc;
use tokio;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Messages sent to the controller.
pub enum MsgFcCtl {
    /// Stop RTP.
    /// Receivers listening to this flexicast channel can close their communication.
    CloseRtp(u64),

    /// New connection from a client.
    /// Indicate the channel to communicate with it and its client ID.
    NewClient((u64, mpsc::Sender<MsgRecv>)),

    // ...
}

/// Messages sent to the receiver.
pub enum MsgRecv {
    
}

/// Controller structure using tokio to handle messages between the flexicast source and the unicast server instances.
pub struct FcController {
    /// The reception channel for the controller.
    rx_fc_ctl: mpsc::Receiver<MsgFcCtl>,

    /// All McAnnounceData to send to new clients.
    mc_announce_data: Vec<McAnnounceData>,

    /// Number of clients.
    nb_clients: u64,

    /// List of all transmission channels to communicate with the receivers.
    /// Indexed by the client ID.
    tx_clients: Vec<mpsc::Sender<MsgRecv>>,
}

impl FcController {
    /// New controller.
    pub fn new(
        rx_fc_ctl: mpsc::Receiver<MsgFcCtl>,
        mc_announce_data: Vec<McAnnounceData>,
    ) -> Self {
        Self {
            rx_fc_ctl,
            mc_announce_data,
            nb_clients: 0,
            tx_clients: Vec::new(),
        }
    }
    /// Run the controller.
    pub async fn run(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                Some(msg) = self.rx_fc_ctl.recv() => self.handle_fc_msg(msg).await?,
                else => debug!("Error in select controller"),
            }
        }

        Ok(())
    }


    /// Handle the reception of a message from the flexicast source channel.
    async fn handle_fc_msg(&mut self, msg: MsgFcCtl) -> Result<()> {
        match msg {
            MsgFcCtl::CloseRtp(id) => println!("Receive a close RTP message from {id}"),
            MsgFcCtl::NewClient((_id, tx)) => {
                // Push new client.
                self.nb_clients += 1;
                self.tx_clients.push(tx);
            },
        }
        
        Ok(())
    }
}