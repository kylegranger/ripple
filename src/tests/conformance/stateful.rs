//! Contains code to start and stop a node with preloaded ledger data.
//!
use std::{io, path::PathBuf, time::Duration};

use crate::{
    setup::{config::ZIGGURAT_DIR, node::NodeBuilder2},
    tools::constants::{NODE_STATE_DIR, TESTNET_NETWORK_ID},
};

#[tokio::test]
#[ignore = "convenience test to tinker with a running node for dev purposes"]
async fn should_start_stop_stateful_node() {
    let path = build_stateful_path().expect("Unable to build stateful path");
    let builder = NodeBuilder2::new(path).expect("Unable to create builder")
        .network_id(TESTNET_NETWORK_ID)
        .validator_token("eyJtYW5pZmVzdCI6IkpBQUFBQUZ4SWUyUDhJZjJTTlFvL3MzZDZReDl6Wld3cVZyWkc1N3VhdWszN2JDRWIxMWJQbk1oQXZSMVRCc3p4OU11Z0Y2eXNZY0FtcHRERWtRZWtaaURURnViWTI0dGxWUzVka1l3UkFJZ1QvRU9LRUluekVVQmh5dWxEQjBydHhaczBPdWltblpmdklucE0rZ1NVd3NDSUJqWjBKOXg2dEtJMm1GcElITXpwUUhVY0RxdjBNK0dWeFNmc1RHWWlQUlpjQkpBRWYwRGZocTlOY2hwMjhPK29vYVZHQUdkbDhLQUxpZCtJK2xBSGVRSXhJSENkZEgveDM0NmMwaDkwSHpGblpuRWxYUDNXNGtQcnNGanNlSmNPYnVpQVE9PSIsInZhbGlkYXRpb25fc2VjcmV0X2tleSI6IjkyNEQxMkE4NzJDNDVENTcwREE0N0FDN0UyMEY5NDQ0QjA1RDE4Nzg3N0UwM0I4RDg1NkY5RjRFM0ZBMDk5NjkifQ==".into())
        .add_args(vec![
            "--valid".into(),
            "--quorum".into(),
            "1".into(),
            "--load".into(),
        ]);
    let node = builder
        .start(true)
        .await
        .expect("Unable to start stateful node");
    tokio::time::sleep(Duration::from_secs(60)).await;
    node.stop().expect("Unable to stop stateful node");
}

fn build_stateful_path() -> io::Result<PathBuf> {
    Ok(home::home_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "couldn't find home directory"))?
        .join(ZIGGURAT_DIR)
        .join(NODE_STATE_DIR))
}
