use std::time::Duration;

use secp256k1::constants::PUBLIC_KEY_SIZE;
use serde::Deserialize;
use tempfile::TempDir;
use tokio::time::sleep;

use crate::{
    protocol::{
        codecs::binary::{BinaryMessage, Payload},
        proto::TmValidatorList,
    },
    setup::node::{Node, NodeType},
    tests::conformance::{perform_expected_message_test, PUBLIC_KEY_TYPES},
    tools::{config::TestConfig, synth_node::SyntheticNode},
};

#[derive(Deserialize)]
struct ValidatorList {
    validators: Vec<Validator>,
}

#[derive(Deserialize)]
struct Validator {
    validation_public_key: String,
    manifest: String,
}

#[tokio::test]
#[allow(non_snake_case)]
async fn c015_TM_VALIDATOR_LIST_COLLECTION_node_should_send_validator_list() {
    // ZG-CONFORMANCE-015

    // Check for a TmValidatorListCollection message.
    let check = |m: &BinaryMessage| {
        if let Payload::TmValidatorListCollection(validator_list_collection) = &m.payload {
            if let Some(blob_info) = validator_list_collection.blobs.first() {
                println!("Blob bytes: {:?}", blob_info.blob);
                let decoded_blob =
                    base64::decode(&blob_info.blob).expect("unable to decode a blob");
                let text = String::from_utf8(decoded_blob)
                    .expect("unable to convert decoded blob bytes to a string");
                println!("json blob: {}", text);
                let validator_list = serde_json::from_str::<ValidatorList>(&text)
                    .expect("unable to deserialize a validator list");
                if validator_list.validators.is_empty() {
                    return false;
                }
                for validator in &validator_list.validators {
                    let key = hex::decode(&validator.validation_public_key)
                        .expect("unable to decode a public key");
                    if key.len() != PUBLIC_KEY_SIZE {
                        panic!("invalid public key length: {}", key.len());
                    }
                    if !PUBLIC_KEY_TYPES.contains(&key[0]) {
                        panic!("invalid public key type: {}", key[0]);
                    }
                    if validator.manifest.is_empty() {
                        panic!("empty manifest");
                    }
                }
                return true;
            }
        }
        false
    };
    perform_expected_message_test(Default::default(), &check).await;
}

#[tokio::test]
async fn c026() {
    // Create stateful node.
    let target = TempDir::new().expect("unable to create TempDir");
    let mut node = Node::builder()
        .log_to_stdout(true)
        .start(target.path(), NodeType::Stateless)
        .await
        .expect("unable to start stateful node");

    let mut test_config = TestConfig::default();
    test_config.synth_node_config.generate_new_keys = false;
    let mut synth_node = SyntheticNode::new(&test_config).await;

    synth_node
        .connect(node.addr())
        .await
        .expect("unable to connect");
    let example_manifest_payload = loop {
        let (_, message) = synth_node.recv_message().await;
        if let Payload::TmManifests(m) = message.payload {
            break m;
        }
    };

    let mut st = example_manifest_payload.list[0].stobject.clone();
    let key =
        hex::decode("02A2C35BE0D8ADDCAA7A1995CB31C7EF6E0EC4BF471BA7481937924114CD57B983").unwrap();
    st[7..40].clone_from_slice(key.as_slice());
    let manifest = base64::encode(st);
    let mb = manifest.as_bytes().to_vec();
    let _payload = Payload::TmValidatorList(TmValidatorList {
        manifest: mb,
        blob: vec![],
        signature: vec![],
        version: 1,
    });
    // synth_node
    //     .unicast(node.addr(), payload)
    //     .expect("unable to send message");

    sleep(Duration::from_secs(300)).await;
    synth_node.shut_down().await;
    node.stop().expect("unable to stop stateful node");
}
