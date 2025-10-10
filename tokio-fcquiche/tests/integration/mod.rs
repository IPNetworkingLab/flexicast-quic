use tokio_fcquiche::FcQuicMsg;

use crate::fixtures::*;

#[tokio::test]
async fn tfc_send_file() {
    let mut server = fcquiche_server("/tmp/tfc_send_file").await;
    let uc_path_config = get_uc_path_config(true);
    let tx = server.get_tx_fc_flow(0).unwrap();

    let (mut recv, mut rx) = fcquiche_client().await;

    // Start both the source and the receiver.
    tokio::spawn(async move {
        server.run(uc_path_config).await.unwrap();
    });
    tokio::spawn(async move {
        recv.run().await.unwrap();
    });

    // Send data on one end, receive it on the other.
    let data = vec![42u8; 1000];
    let msg = FcQuicMsg::Stream((data.clone(), true, 3));
    tx.send(msg).await.unwrap();

    let recv_msg = rx.recv().await.unwrap();
    match recv_msg {
        FcQuicMsg::Close => assert!(false),
        FcQuicMsg::Stream((d, f, s)) => {
            assert!(f);
            assert_eq!(s, 3);
            assert_eq!(d, data);
        },
    }
}
