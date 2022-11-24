use std::time::Duration;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::time::sleep;
// use sha2::Sha512;
// use hex_literal::hex;
use sha2::{Sha512_256, Digest};

use secp256k1::{
    constants::{PUBLIC_KEY_SIZE},
    PublicKey, Secp256k1, SecretKey, Message
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

// let hello = String::from("Hello, world!");


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

// fn extract_public_key_from_manifest(manifest: Vec<u8>) -> String {
//     println!("extractPublicKeyFromManifest, manifest size: {}", manifest.len());
//     let mut i: usize = 0;
//     let mut public_key = vec!(0; 33);
//     while i < manifest.len() {
//         let c = manifest[i];
//         let mut chunklen: usize = 0;
//         i += 1;
//         if (c & 0xf0) == 0x20 {
//             println!("got UINT32 chunk");
//             chunklen = 4;
//         } else if (c & 0xf0) == 0x70 {
//             let subtype: u8;
//             println!("got VL chunk");
//             if c == 0x70 {
//                 subtype = manifest[i];
//                 i += 1;
//             } else {
//                 subtype = c & 0xf;
//             }
//             chunklen = usize::from(manifest[i]);
//             i += 1;
//             println!("got subtype is {}", subtype);
//             println!("got chunklen is {}", chunklen);
//             let end: usize = i + chunklen;
//             if subtype == 0x1 {
//                 public_key.copy_from_slice(&manifest[i..end]);
//                 println!("jkl: currentKey bytes: {:02X?}", public_key);
//             }
//         }
//         println!("skip {} bytes", chunklen);
//         i += usize::from(chunklen);
//         println!("i is now {}", i);
//     }
//     hex::encode_upper(public_key)

// }

fn replace_manifest_public_key(manifest: &Vec<u8>, publicKey: &Vec<u8>)  {
    println!("replace_manifest_public_key, manifest size: {}", manifest.len());
    let mut i: usize = 0;
    while i < manifest.len() {
        let c = manifest[i];
        let mut chunklen: usize = 0;
        i += 1;
        if (c & 0xf0) == 0x20 {
            println!("got UINT32 chunk");
            chunklen = 4;
        } else if (c & 0xf0) == 0x70 {
            let subtype: u8;
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
                manifest[i..i+33].clone_from_slice(publicKey.as_slice());
            }
        }
        println!("skip {} bytes", chunklen);
        i += usize::from(chunklen);
        println!("i is now {}", i);
    }

}

// fn extract_signature_from_manifest(manifest: Vec<u8>) -> Vec<u8> {
//     println!("extractPublicKeyFromManifest, manifest size: {}", manifest.len());
//     let mut i: usize = 0;
//     let mut signature = vec!(0; 70);
//     while i < manifest.len() {
//         let c = manifest[i];
//         let mut chunklen: usize = 0;
//         i += 1;
//         if (c & 0xf0) == 0x20 {
//             println!("got UINT32 chunk");
//             chunklen = 4;
//         } else if (c & 0xf0) == 0x70 {
//             let subtype: u8;
//             println!("got VL chunk");
//             if c == 0x70 {
//                 subtype = manifest[i];
//                 i += 1;
//             } else {
//                 subtype = c & 0xf;
//             }
//             chunklen = usize::from(manifest[i]);
//             i += 1;
//             println!("got subtype is {}", subtype);
//             println!("got chunklen is {}", chunklen);
//             let end: usize = i + chunklen;
//             if subtype == 0x6 {
//                 signature.copy_from_slice(&manifest[i..end]);
//                 println!("jkl: currentKey bytes: {:02X?}", signature);
//             }
//         }
//         println!("skip {} bytes", chunklen);
//         i += usize::from(chunklen);
//         println!("i is now {}", i);
//     }
//     // hex::encode(signature)
//     signature

// }

// fn getManifest() -> Vec<u8>{
//     let manifest: Vec<u8> = vec![ 0x24, 0x00, 0x00, 0x00, 0x02, 0x71, 0x21, 0xED, 0xD9, 0x1F, 0x38, 0x42, 0xDC, 0xBE, 0x8D, 0x5D, 0x2B, 0xF7, 0x55, 0x94, 0x4D, 0xF4, 0x1A, 0xA8, 0xF5, 0x06, 0x8C, 0x15, 0x3E, 0x04, 0x04, 0xBE, 0x13, 0xE2, 0xAE, 0x48, 0xE4, 0x00, 0x0C, 0x44, 0x73, 0x21, 0x03, 0xF8, 0xEF, 0x27, 0xE5, 0x93, 0x39, 0x7F, 0xC9, 0x18, 0x65, 0x98, 0x91, 0x39, 0x46, 0xD8, 0xE4, 0x92, 0xAE, 0xDD, 0xA4, 0xD4, 0x25, 0x0F, 0xA3, 0xCC, 0xEB, 0xF0, 0xE8, 0xA7, 0xB8, 0x1C, 0x97, 0x76, 0x46, 0x30, 0x44, 0x02, 0x20, 0x02, 0x21, 0x23, 0x6E, 0xAA, 0x54, 0x6F, 0x5B, 0x82, 0x58, 0x91, 0x2F, 0xA5, 0x37, 0x26, 0x35, 0x90, 0x8C, 0xA9, 0x17, 0x51, 0x64, 0xD0, 0x24, 0x2D, 0xEB, 0x32, 0x23, 0xE4, 0x90, 0x48, 0x06, 0x02, 0x20, 0x32, 0xDE, 0x95, 0xEF, 0xB1, 0x3A, 0x28, 0x0E, 0x14, 0xEA, 0x11, 0x24, 0x01, 0x35, 0x67, 0x8A, 0x2E, 0x7D, 0xDD, 0x49, 0x20, 0xBB, 0xD8, 0x44, 0xA8, 0x33, 0x65, 0x41, 0x7D, 0x5A, 0xC3, 0x2A, 0x77, 0x18, 0x78, 0x72, 0x70, 0x6C, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x61, 0x74, 0x6F, 0x72, 0x2E, 0x6C, 0x69, 0x6E, 0x6B, 0x70, 0x63, 0x2E, 0x6E, 0x65, 0x74, 0x70, 0x12, 0x40, 0xB3, 0x9A, 0xE8, 0xDC, 0x32, 0x48, 0x95, 0xB2, 0x0D, 0x20, 0x4F, 0xD2, 0x30, 0xE0, 0x92, 0x08, 0x36, 0xBD, 0xDE, 0xC8, 0x71, 0xBC, 0xC4, 0xD3, 0xDF, 0x59, 0x83, 0x30, 0xD2, 0x72, 0x0B, 0x4A, 0x50, 0x86, 0x67, 0x6F, 0x0A, 0x08, 0x60, 0x6D, 0x47, 0x73, 0x33, 0x2E, 0xBE, 0x93, 0x29, 0x70, 0xC6, 0x65, 0xC6, 0x85, 0xF6, 0xC0, 0x49, 0x80, 0xF0, 0x45, 0x02, 0xB2, 0x73, 0x07, 0xB0, 0x0F];
//     manifest
// }

fn create_sha512_half_digest(buffer: &Vec<u8>) {

    let mut hasher = Sha512_256::new();
    hasher.update(buffer);
    let result = hasher.finalize();
    let digest = result.as_slice();
    println!("digest dump: {:02X?}", digest);
}

fn mytest() {

    //
    // 1.  Create key from generated strings
    //
    let master_private_hex = String::from("8484781AE8EEB87D8A5AA38483B5CBBCCE6AD66B4185BB193DDDFAD5C1F4FC06");
    let master_public_hex = String::from("02ED521B8124454DD5B7769C813BD40E8D36E134DD51ACED873B49E165327F6DF2");
    let signing_private_hex = String::from("00F963180681C0D1D51D1128096B8FF8668AFDC41CBDED511D12D390105EFDDC");
    let signing_public_hex = String::from("03859B76317C8AA64F2D253D3547831E413F2663AE2568F7A17E85B283CC8861E4");

    let master_private_bytes = hex::decode(master_private_hex).expect("unable to decode hex");
    let master_public_bytes = hex::decode(master_public_hex).expect("unable to decode hex");
    let signing_private_bytes = hex::decode(signing_private_hex).expect("unable to decode hex");
    let signing_public_bytes = hex::decode(signing_public_hex).expect("unable to decode hex");
    let master_private_key = SecretKey::from_slice(master_private_bytes.as_slice()).expect("unable to create secret key");
    let master_public_key = PublicKey::from_slice(master_public_bytes.as_slice()).expect("unable to create public key");
    let signing_private_key = SecretKey::from_slice(signing_private_bytes.as_slice()).expect("unable to create secret key");
    let signing_public_key = PublicKey::from_slice(signing_public_bytes.as_slice()).expect("unable to create public key");
    println!("master_private bytes is {:02X?}", master_private_key.secret_bytes());
    println!("master_public bytes is {:02X?}", master_public_key.serialize());
    println!("signing_private bytes is {:02X?}", signing_private_key.secret_bytes());
    println!("signing_public bytes is {:02X?}", signing_public_key.serialize());

    //
    // 2. Create first manifest with sequence, public key, signing public key
    //
    let manifest = create_manifest(master_public_bytes, signing_public_bytes);
    println!("mytest, manifest size: {}", manifest.len());
    println!("manifest dump: {:02X?}", manifest);

    //
    // 3. append manifest prefix, sign it with master private key, get signature
    //
    let mut size = 4 + manifest.len();
    let mut prefix: Vec<u8> = vec!(b'M', b'A', b'N', 0);
    let mut prefix_manifest: Vec<u8> = vec!(0; manifest.len() + 4);
    create_sha512_half_digest(&prefix_manifest);

    // let mut prefix_manifest = [0u8; size];
    // for n in 0..4 {
    //     prefix_manifest[n] = prefix[n];
    // }

    // let dummy = hex!("887d04bb1cf1b1554f1b268dfe62d13064ca67ae45348d50d1392ce2d13418ac");
    // let mut myarray: [u8];
    // Message::from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {


    prefix_manifest[0..4].clone_from_slice(prefix.as_slice());
    prefix_manifest[4..4+manifest.len()].clone_from_slice(manifest.clone().as_slice());
    let engine = Secp256k1::new();

    // let msg = Message::from_slice(&dummy).unwrap();
    // let myslice = prefix.as_slice();
    // let message = Message::from_hashed_data( prefix_manifest.as_slice()).expect("msg");

    // let message = Message::from_hashed_data::<sha256::Hash>(prefix_manifest);

    // let message = secp256k1::Message::from_slice(dummy.as_slice()).unwrap();



    // let signature = engine.sign_ecdsa(&message, &master_private_key);
    // let sigbytes = signature.serialize_der();
    // println!("sigbytes len: {:02X?}", sigbytes.len());
    // println!("signature.to_string: {}", signature.to_string());

    //
    // 4.  Create new manifest with mastersignature embeded
    //

    //
    // 5. append manifest prefix, sign it with master private key, get signature
    //

    //
    // 6.  Recreate manifest with signature embedded
    //

    //
    // x.
    //

    //
    // x.
    //

    //
    // x.
    //

    //
    // x.
    //

    //
    // x.
    //



    // let manifest = getManifest();
    // println!("mytest, manifest size: {}", manifest.len());
    // let public_key: String = extract_public_key_from_manifest(manifest.clone());
    // let signature: String = hex::encode(extract_signature_from_manifest(manifest.clone()));
    // println!("kstr: {}", public_key);
    // let mstr = base64::encode(manifest);
    // println!("mstr is {}", mstr);
    // let v = Validator {
    //     validation_public_key: public_key,
    //     manifest: mstr,
    // };
    // let mut vvec: Vec<Validator> = Vec::new();
    // vvec.push(v);
    // let vblob = ValidatorBlob {
    //     sequence: 2022100501,
    //     expiration: 733881600,
    //     validators: vvec
    // };
    // let jstr = serde_json::to_string(&vblob).unwrap();
    // println!("jstr is {}", jstr);

}


fn _gen_keys() {
    let engine = Secp256k1::new();
    let (private_key, public_key) = engine.generate_keypair(&mut secp256k1::rand::thread_rng());
    println!("master private_key is {:02X?}", private_key);
    println!("master public_key is {:02X?}", public_key);
    let master_private = private_key.secret_bytes();
    let master_public = public_key.serialize();
    println!("master_private bytes is {:02X?}", master_private);
    println!("master_public bytes is {:02X?}", master_public);
    let master_private_hex = hex::encode_upper(master_private);
    let master_public_hex = hex::encode_upper(master_public);
    println!("master_private hex string {}", master_private_hex);
    println!("master_public hex string {}", master_public_hex);

    let private_vec = hex::decode(master_private_hex).expect("unable to decode ledger hash");
    let public_vec = hex::decode(master_public_hex).expect("unable to decode ledger hash");
    let private_copy = SecretKey::from_slice(private_vec.as_slice()).expect("msg");
    let public_copy = PublicKey::from_slice(public_vec.as_slice()).expect("msg");
    println!("copy_private bytes is {:02X?}", private_copy.secret_bytes());
    println!("copy_public bytes is {:02X?}", public_copy.serialize());
}

fn create_validator_blob_json() -> String{
    let manifest = getManifest();
    println!("jkl: createValidatorBlobJson, manifest size: {}", manifest.len());
    let public_key: String = extract_public_key_from_manifest(manifest.clone());
    // let signature: String = extract_signature_from_manifest(manifest.clone());
    println!("jkl: public_key: {}", public_key);
    let mstr = base64::encode(manifest);
    println!("jkl: mstr is {}", mstr);
    let v = Validator {
        validation_public_key: public_key,
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
    jstr


    // let engine = Secp256k1::new();
    // let (private_key, public_key) = engine.generate_keypair(&mut secp256k1::rand::thread_rng());
    // println!("private_key is {:02X?}", private_key);
    // println!("public_key is {:02X?}", public_key);


}


fn create_manifest(publicKey: Vec<u8>, signingPubKey: Vec<u8>) -> Vec<u8> {
    let size = 5 + 2 + 33 + 2 + 33;
    let mut manifest: Vec<u8> = vec!(0; size);
    manifest[0] = 0x24;
    manifest[4] = 0x01;
    let mut i = 5;

    // serialize public key
    manifest[i] = 0x71; // field code for "PublicKey"
    manifest[i+1] = 33; // size
    i += 2;
    // publicKey.copy_from_slice(&manifest[i..i+33]);
    manifest[i..i+33].clone_from_slice(publicKey.as_slice());


    i += 33;

    // serialize signing public key
    manifest[i] = 0x73; // field code for "SigningPubKey"
    manifest[i+1] = 33; // size
    i += 2;
    manifest[i..i+33].clone_from_slice(signingPubKey.as_slice());
    i += 33;
    manifest

}



#[tokio::test]
async fn c026() {

    // Create stateful node.
    println!("jkl: here we are----------------------------------------------------------------------------");
    mytest();
    let target = TempDir::new().expect("unable to create TempDir");
    let mut node = Node::builder()
        .log_to_stdout(true)
        .start(target.path(), NodeType::Stateless)
        .await
        .expect("jkl: unable to start stateful node");

    println!("jkl: two----------------------------------------------------------------------------");
    let mut test_config = TestConfig::default();
    test_config.synth_node_config.generate_new_keys = false;
    let mut synth_node = SyntheticNode::new(&test_config).await;
    println!("jkl: 2a----------------------------------------------------------------------------");

    synth_node
        .connect(node.addr())
        .await
        .expect("jkl: unable to connect");
    // let example_manifest_payload = loop {
    //     let (_, message) = synth_node.recv_message().await;
    //     if let Payload::TmManifests(m) = message.payload {
    //         break m;
    //     }
    // };
    println!("jkl: three----------------------------------------------------------------------------");

    // let st = example_manifest_payload.list[0].stobject.clone();
    // let key =
    //     hex::decode("02A2C35BE0D8ADDCAA7A1995CB31C7EF6E0EC4BF471BA7481937924114CD57B983").unwrap();
    //st[7..40].clone_from_slice(key.as_slice());
    //let mut current_key = Vec::new();
    // let mut current_key = vec!(0; 33);
    // current_key.copy_from_slice(&st[7..40]);
    // println!("jkl: currentKey bytes: {:02X?}", current_key);
    // let st = getManifest();
    let manifest = base64::encode(getManifest());
    let mb = manifest.as_bytes().to_vec();
    let blob = base64::encode(create_validator_blob_json());
    let bb = blob.as_bytes().to_vec();
    let svec = extract_signature_from_manifest(getManifest());
    let signature = hex::encode_upper(svec);
    let sb = signature.as_bytes().to_vec();
    println!("jkl:-------------------about to send payload");
    println!("jkl:-------------------manifest\n{}", manifest);
    println!("jkl:-------------------blob\n{}", blob);
    println!("jkl:-------------------signature\n{}", signature);

    let payload = Payload::TmValidatorList(TmValidatorList {
        manifest: mb,
        blob: bb,
        signature: sb,
        version: 1,
    });
    synth_node
        .unicast(node.addr(), payload)
        .expect("jkl: unable to send message");

    sleep(Duration::from_secs(300)).await;
    synth_node.shut_down().await;
    node.stop().expect("jkl: unable to stop stateful node");
}
