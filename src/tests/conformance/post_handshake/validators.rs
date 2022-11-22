use std::time::Duration;

use secp256k1::constants::PUBLIC_KEY_SIZE;
use serde::{Deserialize, Serialize};
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

#[derive(Deserialize,Serialize)]
struct ValidatorList {
    validators: Vec<Validator>,
}

#[derive(Deserialize,Serialize)]
struct Validator {
    validation_public_key: String,
    manifest: String,
}

#[derive(Deserialize, Serialize)]
struct ValidatorBlob {
    sequence: u32,
    expiration: u32,
    validators: Vec<Validator>
}



#[tokio::test]
#[allow(non_snake_case)]
async fn c015_TM_VALIDATOR_LIST_COLLECTION_node_should_send_validator_list() {
    // ZG-CONFORMANCE-015

    // Check for a TmValidatorListCollection message.
    let check = |m: &BinaryMessage| {
        if let Payload::TmValidatorListCollection(validator_list_collection) = &m.payload {
            if let Some(blob_info) = validator_list_collection.blobs.first() {
                println!("Blob bytes: {:02X?}", blob_info.blob);
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


fn mytest() {
    let manifest: Vec<u8> = vec![ 0x24, 0x00, 0x00, 0x00, 0x02, 0x71, 0x21, 0xED, 0xD9, 0x1F, 0x38, 0x42, 0xDC, 0xBE, 0x8D, 0x5D, 0x2B, 0xF7, 0x55, 0x94, 0x4D, 0xF4, 0x1A, 0xA8, 0xF5, 0x06, 0x8C, 0x15, 0x3E, 0x04, 0x04, 0xBE, 0x13, 0xE2, 0xAE, 0x48, 0xE4, 0x00, 0x0C, 0x44, 0x73, 0x21, 0x03, 0xF8, 0xEF, 0x27, 0xE5, 0x93, 0x39, 0x7F, 0xC9, 0x18, 0x65, 0x98, 0x91, 0x39, 0x46, 0xD8, 0xE4, 0x92, 0xAE, 0xDD, 0xA4, 0xD4, 0x25, 0x0F, 0xA3, 0xCC, 0xEB, 0xF0, 0xE8, 0xA7, 0xB8, 0x1C, 0x97, 0x76, 0x46, 0x30, 0x44, 0x02, 0x20, 0x02, 0x21, 0x23, 0x6E, 0xAA, 0x54, 0x6F, 0x5B, 0x82, 0x58, 0x91, 0x2F, 0xA5, 0x37, 0x26, 0x35, 0x90, 0x8C, 0xA9, 0x17, 0x51, 0x64, 0xD0, 0x24, 0x2D, 0xEB, 0x32, 0x23, 0xE4, 0x90, 0x48, 0x06, 0x02, 0x20, 0x32, 0xDE, 0x95, 0xEF, 0xB1, 0x3A, 0x28, 0x0E, 0x14, 0xEA, 0x11, 0x24, 0x01, 0x35, 0x67, 0x8A, 0x2E, 0x7D, 0xDD, 0x49, 0x20, 0xBB, 0xD8, 0x44, 0xA8, 0x33, 0x65, 0x41, 0x7D, 0x5A, 0xC3, 0x2A, 0x77, 0x18, 0x78, 0x72, 0x70, 0x6C, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x61, 0x74, 0x6F, 0x72, 0x2E, 0x6C, 0x69, 0x6E, 0x6B, 0x70, 0x63, 0x2E, 0x6E, 0x65, 0x74, 0x70, 0x12, 0x40, 0xB3, 0x9A, 0xE8, 0xDC, 0x32, 0x48, 0x95, 0xB2, 0x0D, 0x20, 0x4F, 0xD2, 0x30, 0xE0, 0x92, 0x08, 0x36, 0xBD, 0xDE, 0xC8, 0x71, 0xBC, 0xC4, 0xD3, 0xDF, 0x59, 0x83, 0x30, 0xD2, 0x72, 0x0B, 0x4A, 0x50, 0x86, 0x67, 0x6F, 0x0A, 0x08, 0x60, 0x6D, 0x47, 0x73, 0x33, 0x2E, 0xBE, 0x93, 0x29, 0x70, 0xC6, 0x65, 0xC6, 0x85, 0xF6, 0xC0, 0x49, 0x80, 0xF0, 0x45, 0x02, 0xB2, 0x73, 0x07, 0xB0, 0x0F];
    println!("mytest, manifest size: {}", manifest.len());
    let mut i: usize = 0;
    let mut current_key = vec!(0; 33);
    while i < manifest.len() {
        let c = manifest[i];
        let mut chunklen: usize = 0;
        i += 1;
        if (c & 0xf0) == 0x20 {
            println!("got UINT32 chunk");
            chunklen = 4;
        } else if (c & 0xf0) == 0x70 {
            let mut subtype: u8 = 0;
            println!("got VL chunk");
            if c == 0x70 {
                subtype = manifest[i];
                i += 1;
            } else {
                subtype = c & 0xf;
            }
            chunklen = usize::from(manifest[i]);
            i += 1;
            println!("got subtype is {}", subtype);
            println!("got chunklen is {}", chunklen);
            let end: usize = i + chunklen;
            if subtype == 0x1 {
                current_key.copy_from_slice(&manifest[i..end]);
                println!("kyle: currentKey bytes: {:02X?}", current_key);
            }
        }
        println!("skip {} bytes", chunklen);
        i += usize::from(chunklen);
        println!("i is now {}", i);
    }
    let kstr: String = hex::encode_upper(current_key);
    println!("kstr: {}", kstr);
    let mstr = base64::encode(manifest);
    println!("mstr is {}", mstr);
    let v = Validator {
        validation_public_key: kstr,
        manifest: mstr,
    };
    let mut vvec: Vec<Validator> = Vec::new();
    vvec.push(v);
    let vblob = ValidatorBlob {
        sequence: 2022100501,
        expiration: 733881600,
        validators: vvec
    };
    let jstr = serde_json::to_string(&vblob).unwrap();
    println!("jstr is {}", jstr);

}





#[tokio::test]
async fn c026() {
    // Create stateful node.
    println!("kyle: here we are----------------------------------------------------------------------------");
    mytest();
    // let target = TempDir::new().expect("unable to create TempDir");
    // let mut node = Node::builder()
    //     .log_to_stdout(true)
    //     .start(target.path(), NodeType::Stateless)
    //     .await
    //     .expect("unable to start stateful node");

    // println!("kyle: two----------------------------------------------------------------------------");
    // let mut test_config = TestConfig::default();
    // test_config.synth_node_config.generate_new_keys = false;
    // let mut synth_node = SyntheticNode::new(&test_config).await;

    // synth_node
    //     .connect(node.addr())
    //     .await
    //     .expect("unable to connect");
    // let example_manifest_payload = loop {
    //     let (_, message) = synth_node.recv_message().await;
    //     if let Payload::TmManifests(m) = message.payload {
    //         break m;
    //     }
    // };
    // println!("kyle: three----------------------------------------------------------------------------");

    // let st = example_manifest_payload.list[0].stobject.clone();
    // // let key =
    // //     hex::decode("02A2C35BE0D8ADDCAA7A1995CB31C7EF6E0EC4BF471BA7481937924114CD57B983").unwrap();
    // //st[7..40].clone_from_slice(key.as_slice());
    // //let mut current_key = Vec::new();
    // let mut current_key = vec!(0; 33);
    // current_key.copy_from_slice(&st[7..40]);
    // println!("kyle: currentKey bytes: {:02X?}", current_key);
    // let manifest = base64::encode(st);
    // let mb = manifest.as_bytes().to_vec();

    let _payload = Payload::TmValidatorList(TmValidatorList {
        manifest: vec![], // mb,
        blob: vec![],
        signature: vec![],
        version: 1,
    });
    // synth_node
    //     .unicast(node.addr(), payload)
    //     .expect("unable to send message");

    // sleep(Duration::from_secs(300)).await;
    // synth_node.shut_down().await;
    // node.stop().expect("unable to stop stateful node");
}
