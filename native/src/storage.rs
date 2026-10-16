//! Version 2 container. age encrypts metadata; Ed25519 binds public bootstrap
//! channels and ciphertext. No secret is required to check the public signature.
pub(crate) const PASSWORD_WORK_FACTOR: u8 = 20;

use super::*;
const MAGIC: &[u8; 8] = b"YKAK\0\x02\r\n";
const DOMAIN: &[u8] = b"YKA-KEYRING-CONTAINER-2\0";

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Channel { key_tag: String, encrypted: String }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: u32, uuid: String, mode: String, config_sha256: String,
    signing_public: String, channels: Vec<Channel>, recovery: Option<String>, sealed: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Container { body: Header, signature: String }

fn channels(k: &SignedKeyring) -> Result<Vec<Channel>> {
    k.body.devices.iter().map(|d| Ok(Channel {
        key_tag: hex::encode(Sha256::digest(B64.decode(&d.public_key)?)), encrypted: d.envelope.clone()
    })).collect()
}
fn signed_message(body: &Header) -> Result<Vec<u8>> {
    let mut message=DOMAIN.to_vec(); message.extend(serde_json::to_vec(body)?); Ok(message)
}
fn verify_container(c: &Container) -> Result<()> {
    let b=&c.body;
    if b.schema!=2 || !matches!(b.mode.as_str(),"lite"|"full") || b.channels.len()>32
        || (b.channels.is_empty() && b.recovery.is_none()) {return Err("Unsupported Keyring format".into());}
    uuid::Uuid::parse_str(&b.uuid)?;
    let mut tags=std::collections::HashSet::new();
    for channel in &b.channels {
        if channel.key_tag.len()!=64 || hex::decode(&channel.key_tag)?.len()!=32 || !tags.insert(&channel.key_tag) {
            return Err("Invalid Keyring channels".into());
        }
    }
    VerifyingKey::from_bytes(B64.decode(&b.signing_public)?.as_slice().try_into()?)?.verify(
        &signed_message(b)?, &ed25519_dalek::Signature::from_slice(&B64.decode(&c.signature)?)?)?;
    Ok(())
}
fn decode(raw: &[u8]) -> Result<Container> {
    if raw.len()<12 || &raw[..8]!=MAGIC {return Err("Unsupported Keyring format".into());}
    let size=u32::from_le_bytes(raw[8..12].try_into()?) as usize;
    if size>MAX_FRAME-12 || size!=raw.len()-12 {return Err("Invalid Keyring length".into());}
    let c:Container=serde_json::from_slice(&raw[12..])?; verify_container(&c)?; Ok(c)
}
fn decrypt_metadata(c: &Container, p: &Payload) -> Result<SignedKeyring> {
    let identity:age::x25519::Identity=p.metadata_identity.parse().map_err(|_|"Invalid metadata identity")?;
    let encrypted=B64.decode(&c.body.sealed)?;
    let mut clear=Zeroizing::new(Vec::new());
    age::Decryptor::new(encrypted.as_slice())?.decrypt(std::iter::once(&identity as &dyn age::Identity))?
        .take(MAX_FRAME as u64+1).read_to_end(&mut clear)?;
    if clear.len()>MAX_FRAME {return Err("Metadata exceeds size limit".into());}
    let k:SignedKeyring=serde_json::from_slice(&clear)?;
    validate(&k,p)?;
    let b=&c.body;
    if b.uuid!=k.body.uuid || b.mode!=k.body.mode || b.config_sha256!=k.body.config_sha256
        || b.signing_public!=k.body.signing_public || b.channels!=channels(&k)? || b.recovery!=k.body.recovery {
        return Err("Keyring identity mismatch".into());
    }
    Ok(k)
}
pub fn seal(k: &SignedKeyring, p: &Payload) -> Result<Vec<u8>> {
    validate(k,p)?;
    let identity:age::x25519::Identity=p.metadata_identity.parse().map_err(|_|"Invalid metadata identity")?;
    let recipient=identity.to_public();
    let enc=age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
    let mut sealed=Vec::new(); let mut writer=enc.wrap_output(&mut sealed)?;
    writer.write_all(&Zeroizing::new(serde_json::to_vec(k)?))?;writer.finish()?;
    let body=Header{schema:2,uuid:k.body.uuid.clone(),mode:k.body.mode.clone(),config_sha256:k.body.config_sha256.clone(),
        signing_public:k.body.signing_public.clone(),channels:channels(k)?,recovery:k.body.recovery.clone(),sealed:B64.encode(sealed)};
    let signature=B64.encode(key(p)?.sign(&signed_message(&body)?).to_bytes());
    let encoded=serde_json::to_vec(&Container{body,signature})?;
    if encoded.len()>MAX_FRAME-12 {return Err("Keyring exceeds size limit".into());}
    let mut raw=MAGIC.to_vec();raw.extend_from_slice(&(encoded.len() as u32).to_le_bytes());raw.extend(encoded);
    let checked=decode(&raw)?;decrypt_metadata(&checked,p)?;Ok(raw)
}
pub fn open(req: &Request) -> Result<(SignedKeyring, Payload)> {
    open_bytes(req, &read_bounded(&req.root.join(".yka-key"))?, &hash_file(&config(&req.root)?)?)
}
pub fn open_bytes(req: &Request, raw: &[u8], config_hash: &str) -> Result<(SignedKeyring, Payload)> {
    let c=decode(raw)?;
    if (!req.expected_uuid.is_empty() && req.expected_uuid!=c.body.uuid)
        || (!req.expected_public.is_empty() && req.expected_public!=c.body.signing_public) {
        return Err("Vault identity changed".into());
    }
    // Reject a mismatched config using the signed public header before any KDF
    // or private-key operation. The decrypted metadata binding is still checked.
    if config_hash!=c.body.config_sha256 {return Err("SecureFS config/Keyring mismatch".into());}
    // Public channel constraints do not require a password KDF or PIV touch.
    match req.action.as_str() {
        "set-recovery" => {
            if req.new_passphrase.as_ref().is_none_or(|p| p.chars().count()<8) {
                return Err("Password must contain at least 8 characters".into());
            }
            if c.body.recovery.is_some() && req.passphrase.is_none() {return Err("Current password required".into());}
        },
        "remove-recovery" => {
            if c.body.channels.is_empty() {return Err("Cannot remove the last unlock method".into());}
            if req.passphrase.is_some() {return Err("Authenticate with a surviving YubiKey".into());}
        },
        "remove-device" => {
            if c.body.channels.len()==1 && c.body.recovery.is_none() {return Err("Cannot remove the last unlock method".into());}
            if req.device.as_ref().is_some_and(|d|d.serial==req.remove_serial && d.slot==req.remove_slot) {
                return Err("Authenticate with a surviving unlock method".into());
            }
        },
        "add-device" => {
            if c.body.channels.len()>=32 {return Err("Too many authorized keys".into());}
            let device=derive_device(req.new_device.clone().ok_or("Select a new PIV key")?)?;
            let tag=hex::encode(Sha256::digest(B64.decode(&device.public_key)?));
            if c.body.channels.iter().any(|c|c.key_tag==tag) {return Err("Device already authorized".into());}
        },
        _ => {},
    }
    let mut clear=Zeroizing::new(Vec::new());
    if let Some(pass)=&req.passphrase {
        let encrypted=B64.decode(c.body.recovery.as_ref().ok_or("No recovery channel")?)?;
        let mut identity=age::scrypt::Identity::new(SecretString::from(pass.to_string()));
        identity.set_max_work_factor(PASSWORD_WORK_FACTOR);
        age::Decryptor::new(encrypted.as_slice())?.decrypt(std::iter::once(&identity as &dyn age::Identity))?
            .take(MAX_FRAME as u64+1).read_to_end(&mut clear)?;
    } else {
        let expected=derive_device(req.device.clone().ok_or("Select a connected PIV device")?)?;
        let tag=hex::encode(Sha256::digest(B64.decode(&expected.public_key)?));
        let channel=c.body.channels.iter().find(|d|d.key_tag==tag).ok_or("Device public key is not authorized")?;
        let identity:age::plugin::Identity=expected.identity.parse()?;
        let plugin=age::plugin::IdentityPluginV1::new("yubikey", &[identity], Ui::new())?;
        let encrypted=B64.decode(&channel.encrypted)?;
        age::Decryptor::new(encrypted.as_slice())?.decrypt(std::iter::once(&plugin as &dyn age::Identity))?
            .take(MAX_FRAME as u64+1).read_to_end(&mut clear)?;
    }
    if clear.len()>MAX_FRAME {return Err("Payload too large".into());}
    let p:Payload=serde_json::from_slice(&clear)?;
    let k=decrypt_metadata(&c,&p)?;
    if req.passphrase.is_none() {
        let selected=derive_device(req.device.clone().ok_or("Missing device")?)?;
        if !k.body.devices.iter().any(|d|d.serial==selected.serial && d.slot==selected.slot && d.public_key==selected.public_key) {
            return Err("Device public key is not authorized".into());
        }
    }
    if config_hash!=k.body.config_sha256 {return Err("SecureFS config/Keyring mismatch".into());}
    Ok((k,p))
}
pub fn summary(k: &SignedKeyring, root: &Path) -> Result<Value> {
    summary_hash(k, &hash_file(&root.join(".yka-key"))?)
}
pub fn summary_hash(k: &SignedKeyring, keyring_hash: &str) -> Result<Value> {
    let devices:Vec<Value>=k.body.devices.iter().map(|d|json!({"serial":d.serial,"slot":d.slot,"public_key":d.public_key})).collect();
    Ok(json!({"uuid":k.body.uuid,"mode":k.body.mode,"signing_public":k.body.signing_public,
        "generation":k.body.generation,"authorized_keys":devices,"recovery":k.body.recovery.is_some(),
        "keyring_sha256":keyring_hash}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (SignedKeyring,Payload) {
        let mut seed=[0u8;32];OsRng.fill_bytes(&mut seed);
        let p=Payload{uuid:uuid::Uuid::new_v4().to_string(),password:"test-only-volume-secret".into(),
            signing_seed:B64.encode(seed),metadata_identity:age::x25519::Identity::generate().to_string().expose_secret().to_owned()};
        // These tests exercise container encryption/binding only. Actual age
        // password channels and SecureFS are covered by Windows integration.
        let body=Keyring{schema:2,uuid:p.uuid.clone(),generation:7,mode:"lite".into(),config_sha256:"a".repeat(64),
            signing_public:B64.encode(key(&p).unwrap().verifying_key().as_bytes()),experimental:false,devices:vec![],recovery:Some(B64.encode(b"unit-channel"))};
        let signature=B64.encode(key(&p).unwrap().sign(&serde_json::to_vec(&body).unwrap()).to_bytes());
        (SignedKeyring{body,signature},p)
    }
    fn resign(c:&mut Container,p:&Payload) {c.signature=B64.encode(key(p).unwrap().sign(&signed_message(&c.body).unwrap()).to_bytes());}
    #[test]
    fn config_mismatch_precedes_private_unlock_but_not_signature_check() {
        let (k,p)=fixture(); let raw=seal(&k,&p).unwrap();
        let req:Request=serde_json::from_value(json!({"action":"verify"})).unwrap();
        // No device or password exists in this request: a private unlock would fail
        // with a different error. A valid signed header suffices for early rejection.
        assert_eq!(open_bytes(&req,&raw,&"b".repeat(64)).err().unwrap().to_string(),"SecureFS config/Keyring mismatch");
        let mut c=decode(&raw).unwrap(); c.body.config_sha256="b".repeat(64);
        let encoded=serde_json::to_vec(&c).unwrap();
        let mut tampered=MAGIC.to_vec();tampered.extend((encoded.len() as u32).to_le_bytes());tampered.extend(encoded);
        assert_ne!(open_bytes(&req,&tampered,&"c".repeat(64)).err().unwrap().to_string(),"SecureFS config/Keyring mismatch");
        assert_ne!(open_bytes(&req,&raw,&k.body.config_sha256).err().unwrap().to_string(),"SecureFS config/Keyring mismatch");
    }
    #[test]
    fn key_change_constraints_precede_private_unlock() {
        let (k,p)=fixture();let raw=seal(&k,&p).unwrap();
        for (request,message) in [
            (json!({"action":"set-recovery","new_passphrase":"short"}),"Password must contain at least 8 characters"),
            (json!({"action":"set-recovery","new_passphrase":"valid-length"}),"Current password required"),
            (json!({"action":"remove-recovery"}),"Cannot remove the last unlock method"),
        ] {
            let req:Request=serde_json::from_value(request).unwrap();
            assert_eq!(open_bytes(&req,&raw,&k.body.config_sha256).err().unwrap().to_string(),message);
        }
    }
    #[test]
    fn password_creation_matches_unlock_budget() {
        let (_,p)=fixture();let pass="isolated-test-password";
        let raw=B64.decode(recovery_envelope(&p,pass).unwrap()).unwrap();
        let header=String::from_utf8_lossy(&raw);
        let stanza=header.lines().find(|line|line.starts_with("-> scrypt ")).unwrap();
        assert_eq!(stanza.split_whitespace().last().unwrap(),PASSWORD_WORK_FACTOR.to_string());
        let mut identity=age::scrypt::Identity::new(SecretString::from(pass.to_owned()));
        identity.set_max_work_factor(PASSWORD_WORK_FACTOR);
        let mut clear=Zeroizing::new(Vec::new());
        age::Decryptor::new(raw.as_slice()).unwrap().decrypt(std::iter::once(&identity as &dyn age::Identity)).unwrap().read_to_end(&mut clear).unwrap();
        assert_eq!(serde_json::from_slice::<Payload>(&clear).unwrap().uuid,p.uuid);
        let prefix=format!("{}\n",stanza);let mut rejected=raw.clone();
        let offset=raw.windows(prefix.len()).position(|w|w==prefix.as_bytes()).unwrap();
        rejected[offset+prefix.len()-2]=b'1'; // Change only logN=20 to logN=21.
        assert!(matches!(age::Decryptor::new(rejected.as_slice()).unwrap().decrypt(std::iter::once(&identity as &dyn age::Identity)),
            Err(age::DecryptError::ExcessiveWork{required:21,..})));
    }
    #[test]
    fn metadata_confidentiality_and_roundtrip() {
        let (k,p)=fixture();let raw=seal(&k,&p).unwrap();let c=decode(&raw).unwrap();
        assert_eq!(decrypt_metadata(&c,&p).unwrap().body.generation,7);
        for hidden in ["\"generation\"","\"devices\"","\"signing_seed\"","\"metadata_identity\"","test-only-volume-secret"] {
            assert!(!String::from_utf8_lossy(&raw).contains(hidden));
        }
        let (_,wrong)=fixture();assert!(decrypt_metadata(&c,&wrong).is_err());
    }
    #[test]
    fn header_ciphertext_and_binding_reject_tampering() {
        let (k,p)=fixture();let raw=seal(&k,&p).unwrap();
        let mut c=decode(&raw).unwrap();c.body.mode="full".into();assert!(verify_container(&c).is_err());
        resign(&mut c,&p);assert!(decrypt_metadata(&c,&p).is_err());
        let mut c=decode(&raw).unwrap();let mut bytes=B64.decode(&c.body.sealed).unwrap();let n=bytes.len();bytes[n-1]^=1;c.body.sealed=B64.encode(bytes);
        resign(&mut c,&p);assert!(decrypt_metadata(&c,&p).is_err());
        let mut c=decode(&raw).unwrap();c.body.recovery=Some(B64.encode(b"replacement-channel"));resign(&mut c,&p);assert!(decrypt_metadata(&c,&p).is_err());
    }
    #[test]
    fn strict_version_length_duplicate_fields() {
        let (k,p)=fixture();let raw=seal(&k,&p).unwrap();
        for length in [0,7,11,raw.len()-1] {assert!(decode(&raw[..length]).is_err());}
        let mut bad=raw.clone();bad.push(0);assert!(decode(&bad).is_err());
        let mut bad=raw.clone();bad[5]=1;assert!(decode(&bad).is_err());
        let text=String::from_utf8(raw[12..].to_vec()).unwrap().replacen("\"schema\":2","\"schema\":2,\"schema\":2",1);
        let mut bad=MAGIC.to_vec();bad.extend((text.len() as u32).to_le_bytes());bad.extend(text.as_bytes());assert!(decode(&bad).is_err());
    }
    #[test]
    fn every_device_binding_and_endorsement_is_checked() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let (mut k,p)=fixture();let piv=p256::ecdsa::SigningKey::random(&mut OsRng);
        let public=piv.verifying_key().to_encoded_point(true);
        let mut d=derive_device(Device{serial:123456,slot:0x82,public_key:B64.encode(public.as_bytes()),recipient:String::new(),identity:String::new(),endorsement:String::new(),envelope:B64.encode(b"unit-channel")}).unwrap();
        let sig:PivSignature=piv.sign(&endorsement(&k.body));d.endorsement=B64.encode(sig.to_der());k.body.devices.push(d);
        k.signature=B64.encode(key(&p).unwrap().sign(&serde_json::to_vec(&k.body).unwrap()).to_bytes());assert!(seal(&k,&p).is_ok());
        k.body.devices[0].serial+=1;
        k.signature=B64.encode(key(&p).unwrap().sign(&serde_json::to_vec(&k.body).unwrap()).to_bytes());assert!(seal(&k,&p).is_err());
        k.body.devices[0].serial-=1;k.body.devices[0].endorsement=B64.encode([0u8;64]);
        k.signature=B64.encode(key(&p).unwrap().sign(&serde_json::to_vec(&k.body).unwrap()).to_bytes());assert!(seal(&k,&p).is_err());
    }
}
