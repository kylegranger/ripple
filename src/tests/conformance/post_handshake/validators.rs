use std::time::Duration;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::time::sleep;
use sha2::{Sha512, Digest};

use secp256k1::{
    constants::{PUBLIC_KEY_SIZE},
    Secp256k1, SecretKey, Message
};

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
            // let 
            if let Some(blob_info) = validator_list_collection.blobs.first() {
                println!("Blob bytes: {:02X?}", blob_info.blob);
                println!("Manifest bytes: {:02X?}", blob_info.manifest);
                println!("Signature bytes: {:02X?}", blob_info.signature);
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




fn create_sha512_half_digest(buffer: &Vec<u8>) -> [u8; 32]{

    let mut hasher = Sha512::new();
    hasher.update(buffer);
    let result = hasher.finalize();

    // only use first 32 bytes of 64-byte result
    let mut signature = [0u8; 32];
    for i in 0..32 {
        signature[i] = result[i];
    }

    signature
}



fn _gen_keys() {
    let engine = Secp256k1::new();
    let (private_key, public_key) = engine.generate_keypair(&mut secp256k1::rand::thread_rng());
    let secret_bytes = private_key.secret_bytes();
    let public_bytes = public_key.serialize();
    let secret_hex = hex::encode_upper(secret_bytes);
    let public_hex = hex::encode_upper(public_bytes);
    println!("secret key hex string {}", secret_hex);
    println!("public key hex string {}", public_hex);
}

fn create_validator_blob_json(manifest: &Vec<u8>, pkstr: &String) -> String{
    let mstr = base64::encode(manifest);
    let v = Validator {
        validation_public_key: pkstr.clone(),
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
    jstr
}


fn create_signable_manifest(public_key: &Vec<u8>, signing_pub_key: &Vec<u8>) -> Vec<u8> {
    let size = 5 + 2 + public_key.len() + 2 + signing_pub_key.len();
    let mut manifest: Vec<u8> = vec!(0; size);
    manifest[0] = 0x24;
    manifest[4] = 0x01;
    let mut i = 5;

    // serialize public key
    manifest[i] = 0x71; // field code for "PublicKey"
    manifest[i+1] = 33; // size
    i += 2;
    manifest[i..i+33].clone_from_slice(public_key.as_slice());


    i += 33;

    // serialize signing public key
    manifest[i] = 0x73; // field code for "SigningPubKey"
    manifest[i+1] = 33; // size
    i += 2;
    manifest[i..i+33].clone_from_slice(signing_pub_key.as_slice());
    manifest

}

fn create_final_manifest(public_key: &Vec<u8>, signing_pub_key: &Vec<u8>, master_signature: &Vec<u8>, signature: &Vec<u8>) -> Vec<u8> {
    let size = 5 + 2 + public_key.len() + 2 + signing_pub_key.len() + 3 + master_signature.len() + 2 + signature.len();
    let mut manifest: Vec<u8> = vec!(0; size);
    manifest[0] = 0x24;
    manifest[4] = 0x01;
    let mut i = 5;

    // serialize public key
    manifest[i] = 0x71; // field code 1 for "PublicKey"
    manifest[i+1] = 33; // size
    i += 2;
    manifest[i..i+33].clone_from_slice(public_key.as_slice());
    i += 33;

    // serialize signing public key
    manifest[i] = 0x73; // field code 3 for "SigningPubKey"
    manifest[i+1] = 33; // size
    i += 2;
    manifest[i..i+33].clone_from_slice(signing_pub_key.as_slice());
    i += 33;

    // serialize signature
    manifest[i] = 0x76; // field code 6 for "Signature"
    manifest[i+1] = signature.len() as u8;
    i += 2;
    manifest[i..i+signature.len()].clone_from_slice(&signature.as_slice());
    i += signature.len();


    // serialize master signature
    manifest[i] = 0x70; // field code 18 for "MasterSignature"
    manifest[i+1] = 0x12;
    manifest[i+2] = master_signature.len() as u8;
    i += 3;
    manifest[i..i+master_signature.len()].clone_from_slice(&master_signature.as_slice());

    manifest

}


fn sign_buffer(secret_key: &SecretKey, buffer: &Vec<u8>) ->  Vec<u8> {
    let engine = Secp256k1::new();
    let digest = create_sha512_half_digest(buffer);
    let message = Message::from_slice(&digest).unwrap();
    let sig = engine.sign_ecdsa(&message, secret_key);
    let sigser = sig.serialize_der();
    let sigb64 = base64::encode(sigser);
    let sigbytes = base64::decode(sigb64).expect("unable to decode a blob");
    sigbytes
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
    let synth_node = SyntheticNode::new(&test_config).await;

    synth_node
        .connect(node.addr())
        .await
        .expect("unable to connect");
    // let example_manifest_payload = loop {
    //     let (_, message) = synth_node.recv_message().await;
    //     if let Payload::TmManifests(m) = message.payload {
    //         break m;
    //     }
    // };

    // 1. Setup keys & prefix
    let master_secret_hex = String::from("8484781AE8EEB87D8A5AA38483B5CBBCCE6AD66B4185BB193DDDFAD5C1F4FC06");
    let master_public_hex = String::from("02ED521B8124454DD5B7769C813BD40E8D36E134DD51ACED873B49E165327F6DF2");
    let master_secret_bytes = hex::decode(&master_secret_hex).expect("unable to decode hex");
    let master_public_bytes = hex::decode(&master_public_hex).expect("unable to decode hex");
    let master_secret_key = SecretKey::from_slice(master_secret_bytes.as_slice()).expect("unable to create secret key");

    let signing_secret_hex = String::from("00F963180681C0D1D51D1128096B8FF8668AFDC41CBDED511D12D390105EFDDC");
    let signing_public_hex = String::from("03859B76317C8AA64F2D253D3547831E413F2663AE2568F7A17E85B283CC8861E4");
    let signing_secret_bytes = hex::decode(&signing_secret_hex).expect("unable to decode hex");
    let signing_public_bytes = hex::decode(&signing_public_hex).expect("unable to decode hex");
    let signing_secret_key = SecretKey::from_slice(signing_secret_bytes.as_slice()).expect("unable to create secret key");
    let man_prefix: Vec<u8> = vec!(b'M', b'A', b'N', 0);

    // 2. Create signable manifest with sequence, public key, signing public key (without signatures)
    let signable_manifest = create_signable_manifest(&master_public_bytes, &signing_public_bytes);

    // 3. append manifest prefix
    let mut prefixed_signable: Vec<u8> = vec!(0; signable_manifest.len() + 4);
    prefixed_signable[0..4].clone_from_slice(man_prefix.as_slice());
    prefixed_signable[4..4+signable_manifest.len()].clone_from_slice(signable_manifest.clone().as_slice());

    // 4. Sign the signable manifest with master secret key
    let master_signature_bytes = sign_buffer(&master_secret_key, &prefixed_signable);

    // 5. Sign it with signing private key, get signature
    let signature_bytes = sign_buffer(&signing_secret_key, &prefixed_signable);

    // 6. Create final manifest with sequence, public key, signing public key, master signature, signature
    let manifest = create_final_manifest(&master_public_bytes, &signing_public_bytes, &master_signature_bytes, &signature_bytes);

    // 7. Create Validator blob.
    let validator_blob = create_validator_blob_json(&manifest, &master_public_hex);
    let bstr = base64::encode(&validator_blob);
    let blob_bytes = base64::decode(&bstr).expect("unable to decode a blob");
    let bb = bstr.as_bytes().to_vec();

    // 8.  Get signature for blob using master private key
    let blob_signature_bytes = sign_buffer(&signing_secret_key, &blob_bytes);

    // 9. Setup payload, send it
    let mstr = base64::encode(manifest);
    let mb = mstr.as_bytes().to_vec();
    let sstr = hex::encode_upper(blob_signature_bytes);
    let sb = sstr.as_bytes().to_vec();

    let payload = Payload::TmValidatorList(TmValidatorList {
        manifest: mb,
        blob: bb,
        signature: sb,
        version: 1,
    });
    synth_node
        .unicast(node.addr(), payload)
        .expect("unable to send message");

    sleep(Duration::from_secs(300)).await;
    synth_node.shut_down().await;
    node.stop().expect("unable to stop stateful node");
}
