//! Native secret boundary. Never accepts secrets in argv or prints decrypted payloads.
use age::{secrecy::{SecretString, ExposeSecret}, Callbacks};
mod storage;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bech32::{ToBase32, Variant};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use p256::ecdsa::{Signature as PivSignature, VerifyingKey as PivKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::{self, Read, Write}, path::{Path, PathBuf}, process::{Command, Stdio}, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Debug)]
enum AuthFailure { Password, Keyring, Device }
impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.code()) }
}
impl std::error::Error for AuthFailure {}
impl AuthFailure {
    fn code(&self) -> &'static str { match self { Self::Password=>"password_failed", Self::Keyring=>"keyring_invalid", Self::Device=>"device_failed" } }
    fn message(&self) -> &'static str { match self {
        Self::Password=>"Could not unlock with this password.",
        Self::Keyring=>"The vault key file could not be verified.",
        Self::Device=>"The operation failed. See Diagnostics for details.",
    } }
}
const MAX_FRAME: usize = 4 * 1024 * 1024;
static OUTPUT_LOST: AtomicBool = AtomicBool::new(false);
thread_local! { static STAGE: std::cell::Cell<&'static str> = const { std::cell::Cell::new("request") }; }
fn stage(value: &'static str) { STAGE.with(|s| s.set(value)); }
fn error_code(reason: &str) -> &'static str {
    if reason.contains("config/Keyring mismatch") { "config_mismatch" }
    else if reason.contains("identity") || reason.contains("Untrusted volume") { "identity_mismatch" }
    else if reason.contains("not authorized") { "device_unauthorized" }
    else if reason.contains("metadata changed") || reason.contains("Keyring changed") { "metadata_changed" }
    else if reason.contains("timeout") || reason.contains("within 60 seconds") { "backend_timeout" }
    else if reason.contains("Mount") || reason.contains("mount") || reason.contains("SecureFS") { "filesystem_failed" }
    else { "operation_failed" }
}

#[derive(Deserialize)]
struct Request {
    action: String,
    #[serde(default)] guard_handles: Vec<usize>,
    #[serde(default)] prepare: bool,
    #[serde(default)] root: PathBuf,
    #[serde(default)] securefs: PathBuf,
    #[serde(default)] mode: String,
    #[serde(default)] mount_point: String,
    #[serde(default)] volume_label: String,
    #[serde(default)] passphrase: Option<Zeroizing<String>>,
    #[serde(default)] device: Option<Device>,
    #[serde(default)] message: String,
    #[serde(default)] new_device: Option<Device>,
    #[serde(default)] new_passphrase: Option<Zeroizing<String>>,
    #[serde(default)] remove_serial: u32,
    #[serde(default)] remove_slot: u8,
    #[serde(default)] restore_generation: u64,
    #[serde(default)] expected_uuid: String,
    #[serde(default)] expected_public: String,
    #[serde(default)] archive_keyring: String,
    #[serde(default)] archive_config: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Device { serial: u32, slot: u8, public_key: String,
    #[serde(default)] recipient: String, #[serde(default)] identity: String,
    #[serde(default)] endorsement: String, #[serde(default)] envelope: String }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Keyring {
    schema: u32, uuid: String, generation: u64, mode: String,
    config_sha256: String, signing_public: String, experimental: bool,
    devices: Vec<Device>, recovery: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedKeyring { body: Keyring, signature: String }
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Payload { uuid: String, password: String, signing_seed: String, metadata_identity: String }

fn emit(v: Value) { let mut out=io::stdout().lock();
    if writeln!(out,"{}",v).is_err() || out.flush().is_err(){OUTPUT_LOST.store(true,Ordering::SeqCst);}
}
fn frame() -> Result<Zeroizing<String>> {
    let mut v = Zeroizing::new(Vec::new());
    for c in io::stdin().bytes() { let b = c?; if b == b'\n' { break; }
        if v.len() == MAX_FRAME { return Err("IPC frame exceeds limit".into()); } v.push(b); }
    if v.is_empty() { return Err("IPC closed".into()); }
    Ok(Zeroizing::new(String::from_utf8(v.to_vec())?))
}
#[derive(Clone)]
struct Ui { prompted: Arc<AtomicBool> }
impl Ui { fn new() -> Self { Self { prompted: Arc::new(AtomicBool::new(false)) } } }
impl Callbacks for Ui {
    fn display_message(&self, m: &str) {
        if matches!(m,"YKA:PIN_INCORRECT"|"YKA:PIN_BLOCKED") {
            let blocked=m=="YKA:PIN_BLOCKED";
            emit(json!({"event":"error","message":if blocked {"The YubiKey PIN is blocked."} else {"Incorrect YubiKey PIN."},
                "code":if blocked {"pin_blocked"} else {"pin_incorrect"},"stage":"authentication"}));
            return;
        }
        let message=match m {
            "YKA:TOUCH"=>"Please touch the selected YubiKey to unlock this vault.",
            "YKA:CRYPTO"=>"The YubiKey is processing the unlock request. Please wait…",
            _=>"Waiting for the selected YubiKey. Check that it is connected.",
        };
        emit(json!({"event":"touch","message":message}));
    }
    fn confirm(&self, _m: &str, _yes: &str, _no: Option<&str>) -> Option<bool> { Some(false) }
    fn request_public_string(&self, _: &str) -> Option<String> { None }
    fn request_passphrase(&self, _: &str) -> Option<SecretString> {
        if self.prompted.swap(true, Ordering::SeqCst) { return None; }
        emit(json!({"event":"pin"}));
        let raw=frame().ok()?;
        #[derive(Deserialize)] struct Pin { pin: Zeroizing<String> }
        let reply: Pin=serde_json::from_str(&raw).ok()?;
        Some(SecretString::from(reply.pin.to_string()))
    }
}
fn derive_device(mut d: Device) -> Result<Device> {
    if !(0x82..=0x95).contains(&d.slot) { return Err("Only PIV retired slots are supported".into()); }
    let public=p256::PublicKey::from_sec1_bytes(&B64.decode(&d.public_key)?)?;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point=public.to_encoded_point(true);
    d.public_key=B64.encode(point.as_bytes());
    d.recipient=bech32::encode("age1yubikey", point.as_bytes().to_base32(),Variant::Bech32)?;
    let tag=Sha256::digest(point.as_bytes());
    let mut stub=d.serial.to_le_bytes().to_vec();stub.push(d.slot);stub.extend_from_slice(&tag[..4]);
    d.identity=bech32::encode("age-plugin-yubikey-",stub.to_base32(),Variant::Bech32)?.to_uppercase();
    Ok(d)
}
fn endorsement(k: &Keyring) -> Vec<u8> {
    // Fixed schema + tuple, unambiguous and domain-separated from other PIV signatures.
    serde_json::to_vec(&json!(["YKA-VAULT-ENDORSEMENT-1",k.uuid,k.signing_public])).unwrap()
}
fn key(p: &Payload) -> Result<SigningKey> {
    let bytes=Zeroizing::new(B64.decode(&p.signing_seed)?);
    Ok(SigningKey::from_bytes(bytes.as_slice().try_into()?))
}
fn config(root: &Path) -> Result<PathBuf> {
    for name in [".config.pb", ".securefs.json"] { let p=root.join(name);if p.is_file(){return Ok(p);} }
    Err("SecureFS configuration missing".into())
}
fn hash_file(p: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(read_bounded(p)?)))
}
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut options=fs::OpenOptions::new();options.read(true);
    #[cfg(windows)] {use std::os::windows::fs::OpenOptionsExt;options.custom_flags(0x00200000).share_mode(1);}
    let mut file=options.open(path)?;
    #[cfg(windows)] {use std::os::windows::fs::MetadataExt;
        if file.metadata()?.file_attributes() & 0x400 != 0 {return Err("Reparse point rejected".into());}}
    if file.metadata()?.len()>MAX_FRAME as u64 {return Err("Metadata exceeds size limit".into());}
    let mut raw=Vec::new();(&mut file).take(MAX_FRAME as u64+1).read_to_end(&mut raw)?;
    if raw.len()>MAX_FRAME {return Err("Metadata exceeds size limit".into());}Ok(raw)
}
fn pin_paths(root: &Path) -> Result<Vec<fs::File>> {
    let mut pins=Vec::new();
    if root.as_os_str().is_empty(){return Ok(pins);}
    let mut paths:Vec<PathBuf>=root.ancestors().map(Path::to_path_buf).collect();paths.reverse();
    for path in paths {
        if !path.exists(){continue;}
        let mut options=fs::OpenOptions::new();options.read(true);
        #[cfg(windows)] {use std::os::windows::fs::OpenOptionsExt;options.custom_flags(0x02200000).share_mode(3);}
        let file=options.open(path)?;
        #[cfg(windows)] {use std::os::windows::fs::MetadataExt;
            if file.metadata()?.file_attributes() & 0x400 != 0 {return Err("Reparse directory rejected".into());}}
        pins.push(file);
    }Ok(pins)
}
fn validate(k: &SignedKeyring, p: &Payload) -> Result<()> {
    if k.body.schema!=2 || p.uuid!=k.body.uuid { return Err("Keyring identity mismatch".into()); }
    let signing=key(p)?;
    if B64.encode(signing.verifying_key().as_bytes())!=k.body.signing_public { return Err("Untrusted volume signing identity".into()); }
    let pubkey=VerifyingKey::from_bytes(B64.decode(&k.body.signing_public)?.as_slice().try_into()?)?;
    let signature=ed25519_dalek::Signature::from_slice(&B64.decode(&k.signature)?)?;
    pubkey.verify(&serde_json::to_vec(&k.body)?,&signature)?;
    if !matches!(k.body.mode.as_str(),"lite"|"full") || k.body.devices.len()>32 || (k.body.devices.is_empty() && k.body.recovery.is_none()) {return Err("Invalid Keyring channels".into());}
    let mut seen=std::collections::HashSet::new();
    for d in &k.body.devices {
        let derived=derive_device(d.clone())?;
        if derived.public_key!=d.public_key || derived.recipient!=d.recipient || derived.identity!=d.identity || !seen.insert(&d.public_key) {
            return Err("Invalid PIV binding".into());
        }
        PivKey::from_sec1_bytes(&B64.decode(&d.public_key)?)?.verify(&endorsement(&k.body),&PivSignature::from_der(&B64.decode(&d.endorsement)?)?)?;
    }
    Ok(())
}
fn unlock(req: &Request) -> Result<(SignedKeyring,Payload)> { stage("authentication"); storage::open(req) }
fn unwrap_payload(k: &SignedKeyring, passphrase: Option<&Zeroizing<String>>, device: Option<&Device>) -> Result<Payload> {
    let mut clear=Zeroizing::new(Vec::new());
    if let Some(pass)=passphrase {
        let encrypted=B64.decode(k.body.recovery.as_ref().ok_or("Password unlock is not enabled for this vault")?)?;
        let mut identity=age::scrypt::Identity::new(SecretString::from(pass.to_string()));
        identity.set_max_work_factor(storage::PASSWORD_WORK_FACTOR);
        let decryptor=age::Decryptor::new(encrypted.as_slice())?;
        decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?.take(MAX_FRAME as u64+1).read_to_end(&mut clear)?;
    } else {
        let expected=derive_device(device.cloned().ok_or("Select a connected PIV device")?)?;
        let d=k.body.devices.iter().find(|d|d.serial==expected.serial&&d.slot==expected.slot&&d.public_key==expected.public_key).ok_or("Device public key is not authorized")?;
        let verifying=PivKey::from_sec1_bytes(&B64.decode(&expected.public_key)?)?;
        verifying.verify(&endorsement(&k.body), &PivSignature::from_der(&B64.decode(&d.endorsement)?)?)?;
        let identity: age::plugin::Identity=expected.identity.parse()?;
        let plugin=age::plugin::IdentityPluginV1::new("yubikey", &[identity], Ui::new())?;
        let encrypted=B64.decode(&d.envelope)?;
        let decryptor=age::Decryptor::new(encrypted.as_slice())?;
        decryptor.decrypt(std::iter::once(&plugin as &dyn age::Identity))?.take(MAX_FRAME as u64+1).read_to_end(&mut clear)?;
    }
    if clear.len()>MAX_FRAME {return Err("Payload too large".into());}
    let p:Payload=serde_json::from_slice(&clear)?;
    validate(&k,&p)?;
    Ok(p)
}
fn encrypt_hardware(p: &Payload, d: &Device) -> Result<String> {
    let recipient:age::plugin::Recipient=d.recipient.parse()?;
    let plugin=age::plugin::RecipientPluginV1::new("yubikey", &[recipient], &[], Ui::new())?;
    let enc=age::Encryptor::with_recipients(std::iter::once(&plugin as &dyn age::Recipient))?;
    let mut encrypted=Vec::new();let mut writer=enc.wrap_output(&mut encrypted)?;
    writer.write_all(&Zeroizing::new(serde_json::to_vec(p)?))?;writer.finish()?;
    Ok(B64.encode(encrypted))
}
fn save(root: &Path, body: Keyring, p: &Payload) -> Result<()> {
    let signature=B64.encode(key(p)?.sign(&serde_json::to_vec(&body)?).to_bytes());
    let signed=SignedKeyring{body,signature};validate(&signed,p)?;
    let path=root.join(".yka-key");let tmp=root.join(".yka-key.partial");
    let mut out=fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    out.write_all(&storage::seal(&signed,p)?)?;out.sync_all()?;drop(out);
    if path.exists(){return Err("Keyring already exists; no automatic overwrite".into());}fs::rename(tmp,path)?;
    Ok(())
}
// Bound creation and every unlock to the same existing memory/security budget.
// This does not rewrite or weaken existing age envelopes.
fn password_encryptor(pass: &str) -> Result<age::Encryptor> {
    let mut recipient=age::scrypt::Recipient::new(SecretString::from(pass.to_owned()));
    recipient.set_work_factor(storage::PASSWORD_WORK_FACTOR);
    Ok(age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?)
}
fn recovery_envelope(p: &Payload, pass: &str) -> Result<String> {
    if pass.chars().count()<8 { return Err("Password must contain at least 8 characters".into()); }
    let enc=password_encryptor(pass)?;
    let mut bytes=Vec::new();let mut writer=enc.wrap_output(&mut bytes)?;
    writer.write_all(&Zeroizing::new(serde_json::to_vec(p)?))?;writer.finish()?;Ok(B64.encode(bytes))
}
fn replace_keyring(root: &Path, signed: &SignedKeyring, p: &Payload, original: &[u8]) -> Result<()> {
    stage("keyring_commit");
    let replacement=storage::seal(signed,p)?;
    if replacement.len()>MAX_FRAME {return Err("Updated Keyring exceeds size limit".into());}
    let path=root.join(".yka-key");
    if read_bounded(&path)?!=original { return Err("Keyring changed during update".into()); }
    let nonce=uuid::Uuid::new_v4().to_string();
    let backup=root.join(format!(".yka-key-rollback-{}",nonce));
    let mut old=fs::OpenOptions::new().write(true).create_new(true).open(&backup)?;
    old.write_all(original)?;old.sync_all()?;drop(old);
    let staging=root.join(format!(".yka-key-{}.partial",nonce));
    let mut file=fs::OpenOptions::new().write(true).create_new(true).open(&staging)?;
    file.write_all(&replacement)?;file.sync_all()?;drop(file);
    #[cfg(windows)] {
        use std::os::windows::ffi::OsStrExt;
        #[link(name="kernel32")] extern "system" { fn MoveFileExW(from:*const u16,to:*const u16,flags:u32)->i32; }
        let from:Vec<u16>=staging.as_os_str().encode_wide().chain(Some(0)).collect();
        let to:Vec<u16>=path.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe{MoveFileExW(from.as_ptr(),to.as_ptr(),9)}==0 {return Err(io::Error::last_os_error().into());}
    }
    #[cfg(not(windows))] fs::rename(staging,path)?;
    Ok(())
}
// All fallible paths after starting SecureFS converge on cleanup. A hard process
// kill cannot run Drop; the parent retains the lease and reports Unknown.
struct MountCleanup<'a> { req: &'a Request, owner: Option<String>, child: std::process::Child }
impl MountCleanup<'_> {
    fn finished(&mut self) -> Result<bool> {
        if self.child.try_wait()?.is_none() { return Ok(false); }
        if !mounted(self.req)? { return Ok(true); }
        // Another filesystem may reuse this path after our foreground child
        // exits. Never unmount that replacement or retain our obsolete lease.
        Ok(self.owner.as_ref().is_some_and(|owner| mount_device(self.req).is_ok_and(|current| current != *owner)))
    }
    fn stop(&mut self) -> Result<()> {
        if self.finished()? { return Ok(()); }
        if self.owner.is_none() {
            // This is our foreground child, before a mount was acknowledged.
            // Stop it before releasing the lease: it must not mount later.
            if self.child.try_wait()?.is_none() { self.child.kill()?; }
            wait_child_exit(&mut self.child, 10)?;
            if mounted(self.req)? { return Err("An unconfirmed mount remains. Use Recover Mount.".into()); }
        } else {
            unmount_owned(self.req, self.owner.as_deref())?;
            wait_child_exit(&mut self.child, 10)?;
        }
        Ok(())
    }
}
impl Drop for MountCleanup<'_> {
    fn drop(&mut self) {
        if self.stop().is_ok() { return; }
        // One automatic cleanup attempt. Keep ownership pinned while an explicit
        // Recover Mount can unmount the exact recorded device from another process.
        // Do not repeatedly issue destructive commands after losing our controller.
        while !self.finished().unwrap_or(false) { std::thread::sleep(Duration::from_secs(2)); }
    }
}
fn wait_child_exit(child: &mut std::process::Child, seconds: u64) -> Result<()> {
    let deadline=Instant::now()+Duration::from_secs(seconds);
    while child.try_wait()?.is_none() {
        if Instant::now()>deadline {return Err("SecureFS is still stopping. Retry mount recovery.".into());}
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}
fn mount_device(req: &Request) -> Result<String> {
    #[cfg(windows)] {
        use std::os::windows::{fs::OpenOptionsExt,io::AsRawHandle};
        #[link(name="kernel32")] extern "system" { fn GetFinalPathNameByHandleW(h:*mut std::ffi::c_void,p:*mut u16,n:u32,flags:u32)->u32; }
        let point=if req.mount_point.len()==2 {format!("{}\\",req.mount_point)} else {req.mount_point.clone()};
        let file=fs::OpenOptions::new().access_mode(0).custom_flags(0x02000000).share_mode(7).open(point)?;
        let mut buffer=vec![0u16;32768];
        let n=unsafe{GetFinalPathNameByHandleW(file.as_raw_handle(),buffer.as_mut_ptr(),buffer.len() as u32,2)};
        if n==0 || n as usize>=buffer.len(){return Err("Mount device identity unavailable".into());}
        Ok(String::from_utf16(&buffer[..n as usize])?)
    }
    #[cfg(not(windows))] Ok(req.mount_point.clone())
}
fn unmount_owned(req:&Request,owner:Option<&str>)->Result<()> {
    if !mounted(req)?{return Ok(());}
    if owner.is_none() || owner!=Some(mount_device(req)?.as_str()) {return Err("Mount ownership changed or unknown".into());}
    unmount(req)
}
fn command(req: &Request) -> Command {
    let mut c=Command::new(&req.securefs);
    #[cfg(windows)] { use std::os::windows::process::CommandExt;c.creation_flags(0x08000000); }
    c
}
fn wait_child(child: &mut std::process::Child, seconds: u64) -> Result<std::process::ExitStatus> {
    let deadline=Instant::now()+Duration::from_secs(seconds);
    loop {
        if let Some(status)=child.try_wait()? {return Ok(status);}
        if Instant::now()>deadline {let _=child.kill();let _=child.wait();return Err("Backend timeout".into());}
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn run_password(req: &Request, args: &[String], password: &str, confirm: bool) -> Result<()> {
    stage("securefs_create");
    let mut child=command(req).args(args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    let mut input=child.stdin.take().ok_or("Backend input unavailable")?;
    writeln!(input,"{}",password)?;if confirm{writeln!(input,"{}",password)?;}drop(input);
    // Backend output intentionally never copied into exceptions, logs or IPC.
    if !wait_child(&mut child,120)?.success(){return Err("SecureFS operation failed (no sensitive backend output retained)".into());}Ok(())
}
fn mounted(req: &Request) -> Result<bool> {
    let mut child=command(req).args(["ismount",&req.mount_point]).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    let status=wait_child(&mut child,10)?;
    match status.code(){Some(0)=>Ok(true),Some(1)=>Ok(false),_=>Err("Mount state unknown".into())}
}
fn unmount(req:&Request)->Result<()> {
    stage("securefs_unmount");
    let mut child=command(req).args(["unmount",&req.mount_point]).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    let _=wait_child(&mut child,15)?;
    let deadline=Instant::now()+Duration::from_secs(10);
    while Instant::now()<deadline {if !mounted(req)?{return Ok(());}std::thread::sleep(Duration::from_millis(100));}
    Err("Unmount failed: volume may still expose plaintext".into())
}
fn execute(mut req: Request) -> Result<()> {
    if matches!(req.action.as_str(), "archive-verify"|"archive-restore") {
        stage("authentication");
        // No filesystem path or metadata file is needed before authentication.
        let raw=B64.decode(&req.archive_keyring)?;
        let config_raw=B64.decode(&req.archive_config)?;
        let config_hash=hex::encode(Sha256::digest(&config_raw));
        let (mut k,p)=storage::open_bytes(&req,&raw,&config_hash)?;
        let mut info=storage::summary_hash(&k,&hex::encode(Sha256::digest(&raw)))?;
        if req.action=="archive-verify" {info["event"]=json!("result");emit(info);return Ok(());}
        info["event"]=json!("verified");emit(info);
        let reply:Value=serde_json::from_str(&frame()?)?;
        if reply["action"]!="continue" {return Err("Operation cancelled".into());}
        let root=PathBuf::from(reply["root"].as_str().ok_or("Missing restore destination")?);
        if !root.is_absolute(){return Err("Restore path must be absolute".into());}
        let _pins=pin_paths(&root)?;
        if read_bounded(&root.join(".yka-key"))?!=raw || hash_file(&config(&root)?)?!=config_hash {
            return Err("Authenticated backup metadata changed".into());
        }
        k.body.generation=k.body.generation.max(req.restore_generation).checked_add(1).ok_or("Generation limit")?;
        k.signature=B64.encode(key(&p)?.sign(&serde_json::to_vec(&k.body)?).to_bytes());
        replace_keyring(&root,&k,&p,&raw)?;
        let mut info=storage::summary(&k,&root)?;info["event"]=json!("result");emit(info);return Ok(());
    }
    let _pins=pin_paths(&req.root)?;
    // One operation, one unwrap. No decrypted material crosses the IPC boundary.
    // Python validates archive provenance before allowing the operation to proceed.
    let mut prepared = if req.prepare {
        if !matches!(req.action.as_str(), "restore-revision"|"mount"|"sign"|"add-device"|"remove-device"|"set-recovery"|"remove-recovery") {
            return Err("Unsupported prepared operation".into());
        }
        let original=read_bounded(&req.root.join(".yka-key"))?;
        let (k,mut p)=unlock(&req)?;
        if req.action=="sign" {p.password.zeroize();req.passphrase=None;}
        let mut info=storage::summary(&k,&req.root)?;info["event"]=json!("verified");emit(info);
        let reply:Value=serde_json::from_str(&frame()?)?;
        if reply["action"]!="continue" {return Err("Operation cancelled".into());}
        if read_bounded(&req.root.join(".yka-key"))?!=original || hash_file(&config(&req.root)?)?!=k.body.config_sha256 {
            return Err("Vault metadata changed during operation".into());
        }
        if req.action=="sign" {req.message=reply["message"].as_str().ok_or("Missing archive digest")?.to_owned();}
        Some((k,p))
    } else {None};
    match req.action.as_str() {
        "derive-device"=>{emit(json!({"event":"result","device":derive_device(req.device.take().ok_or("Missing device")?)?}));},
        "create"=>{
            stage("keyring_create");
            if req.mode!="lite"&&req.mode!="full"{return Err("Unknown SecureFS mode".into());}
            let mut seed=Zeroizing::new([0u8;32]);let mut password=Zeroizing::new([0u8;32]);OsRng.fill_bytes(seed.as_mut());OsRng.fill_bytes(password.as_mut());
            let p=Payload{uuid:uuid::Uuid::new_v4().to_string(),password:B64.encode(password.as_slice()),signing_seed:B64.encode(seed.as_slice()),metadata_identity:age::x25519::Identity::generate().to_string().expose_secret().to_owned()};
            let mut body=Keyring{schema:2,uuid:p.uuid.clone(),generation:1,mode:req.mode.clone(),config_sha256:String::new(),signing_public:B64.encode(key(&p)?.verifying_key().as_bytes()),experimental:true,devices:vec![],recovery:None};
            if let Some(device)=req.device.take(){
                let mut d=derive_device(device)?;let message=endorsement(&body);
                emit(json!({"event":"piv_sign","message":B64.encode(&message)}));
                let reply:Value=serde_json::from_str(&frame()?)?;
                d.endorsement=reply["signature"].as_str().ok_or("PIV signature required")?.to_owned();
                PivKey::from_sec1_bytes(&B64.decode(&d.public_key)?)?.verify(&message,&PivSignature::from_der(&B64.decode(&d.endorsement)?)?)?;
                emit(json!({"event":"progress","message":"Securing the vault key for your YubiKey…"}));
                d.envelope=encrypt_hardware(&p,&d)?;body.devices.push(d);
            }
            if let Some(pass)=&req.passphrase {
                if pass.chars().count()<8{return Err("Password must contain at least 8 characters".into());}
                emit(json!({"event":"progress","message":"Setting up password protection. This may take a few seconds…"}));
                let enc=password_encryptor(pass)?;let mut ciphertext=Vec::new();let mut writer=enc.wrap_output(&mut ciphertext)?;
                writer.write_all(&Zeroizing::new(serde_json::to_vec(&p)?))?;writer.finish()?;body.recovery=Some(B64.encode(ciphertext));
            }
            if body.devices.is_empty()&&body.recovery.is_none(){return Err("No unlock channel".into());}
            let mut args=vec!["create".into(),req.root.to_string_lossy().into_owned(),"--format".into(),req.mode.clone()];
            if req.mode=="full"{args.extend(["--case".into(),"insensitive".into()]);}
            emit(json!({"event":"progress","message":"Creating the encrypted vault with SecureFS…"}));
            run_password(&req,&args,&p.password,true)?;body.config_sha256=hash_file(&config(&req.root)?)?;save(&req.root,body,&p)?;
            emit(json!({"event":"result","uuid":p.uuid,"experimental":true}));
        },
        "mount"=>{
            let (k,p)=match prepared.take(){Some(value)=>value,None=>unlock(&req)?};
            stage("securefs_mount");
            req.passphrase=None;
            if mounted(&req)?{return Err("Mount target already occupied".into());}
            // Own the actual filesystem process. SecureFS -b creates a detached
            // grandchild which can finish mounting after its launcher is cancelled.
            let mut args=vec!["mount".into(),req.root.to_string_lossy().into_owned(),req.mount_point.clone()];
            if req.volume_label.encode_utf16().count() > 32 || req.volume_label.chars().any(|c| c.is_control() || ",\\/:*?\"<>|".contains(c)) { return Err("Invalid Windows volume label".into()); }
            if !req.volume_label.is_empty() { args.extend(["-o".into(),format!("volname={}",req.volume_label)]); }
            let child=command(&req).args(&args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
            let mut cleanup=MountCleanup{req:&req,owner:None,child};
            {
                let mut input=cleanup.child.stdin.take().ok_or("Backend input unavailable")?;
                writeln!(input,"{}",p.password)?;
            }
            drop(p);
            // Keep reading cancellation/EOF while waiting for the filesystem.
            let (tx,rx)=std::sync::mpsc::channel();
            std::thread::spawn(move || {
                while let Ok(raw)=frame() {
                    let Ok(message)=serde_json::from_str::<Value>(&raw) else {break;};
                    if tx.send(message).is_err(){break;}
                }
            });
            let deadline=Instant::now()+Duration::from_secs(60);
            let startup=(|| -> Result<()> {
                loop {
                    match rx.try_recv() {
                        Ok(message) if message["action"]=="unmount" || message["action"]=="cancel" => return Err("Mount cancelled.".into()),
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => return Err("Mount cancelled: controller disconnected.".into()),
                        _=>{}
                    }
                    if cleanup.child.try_wait()?.is_some(){return Err("SecureFS could not start the mount. Check the mount folder and permissions, then try another location.".into());}
                    if mounted(&req)? {
                        cleanup.owner=Some(mount_device(&req)?);
                        break;
                    }
                    if Instant::now()>deadline{return Err("SecureFS did not mount within 60 seconds. Check the mount location and retry.".into());}
                    std::thread::sleep(Duration::from_millis(100));
                }
                Ok(())
            })();
            if let Err(error)=startup {
                emit(json!({"event":"error","message":error.to_string(),"code":error_code(&error.to_string()),"stage":"securefs_mount"}));
                drop(cleanup);
                return Ok(());
            }
            emit(json!({"event":"mounted","uuid":k.body.uuid,"mount_device":cleanup.owner,"experimental":true}));
            if OUTPUT_LOST.load(Ordering::SeqCst){return Err("Supervisor output closed".into());}
            // This process inherits the manager lock. Keep it until actual unmount.
            loop {
                match rx.recv_timeout(Duration::from_millis(500)){
                    Ok(message)=>{
                        if message["action"]=="unmount" {match cleanup.stop(){Ok(())=>{emit(json!({"event":"unmounted"}));break;},Err(_)=>emit(json!({"event":"unmount_failed","mounted":true}))}}
                        else if message["action"]=="status" {emit(json!({"event":"status","mounted":mounted(&req)?}));}
                    },
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)=>{
                        if cleanup.child.try_wait()?.is_some(){break;}
                    },
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected)=>{ // Parent died: best effort unmount, never abandon a live mount lock.
                        break; // Drop retries safe cleanup while retaining the lease.
                    }
                }
                if OUTPUT_LOST.load(Ordering::SeqCst){return Err("Supervisor output closed".into());}
            }
            drop(cleanup);
        },
        "add-device"|"remove-device"|"set-recovery"|"remove-recovery"=>{
            let original=read_bounded(&req.root.join(".yka-key"))?;
            let (mut k,p)=match prepared.take(){Some(value)=>value,None=>unlock(&req)?};
            stage("keyring_update");
            if req.action=="set-recovery" && k.body.recovery.is_some() && req.passphrase.is_none() {
                return Err("Current password required".into());
            }
            if req.action=="add-device" {
                let mut d=derive_device(req.new_device.clone().ok_or("Select a new PIV key")?)?;
                if k.body.devices.iter().any(|v|v.public_key==d.public_key || (v.serial==d.serial && v.slot==d.slot)) {return Err("Device already authorized".into());}
                emit(json!({"event":"piv_sign","new_device":true,"message":B64.encode(endorsement(&k.body))}));
                let reply:Value=serde_json::from_str(&frame()?)?;
                d.endorsement=reply["signature"].as_str().ok_or("PIV signature missing")?.to_owned();
                PivKey::from_sec1_bytes(&B64.decode(&d.public_key)?)?.verify(&endorsement(&k.body),&PivSignature::from_der(&B64.decode(&d.endorsement)?)?)?;
                d.envelope=encrypt_hardware(&p,&d)?;k.body.devices.push(d);
            } else if req.action=="remove-device" {
                let before=k.body.devices.len();
                k.body.devices.retain(|d| !(d.serial==req.remove_serial && d.slot==req.remove_slot));
                if before==k.body.devices.len(){return Err("Device not authorized".into());}
            } else if req.action=="set-recovery" {
                k.body.recovery=Some(recovery_envelope(&p,req.new_passphrase.as_ref().ok_or("New password missing")?)?);
            } else { k.body.recovery=None; }
            if k.body.devices.is_empty() && k.body.recovery.is_none(){return Err("Cannot remove the last unlock method".into());}
            k.body.generation=k.body.generation.max(req.restore_generation).checked_add(1).ok_or("Generation limit")?;
            k.signature=B64.encode(key(&p)?.sign(&serde_json::to_vec(&k.body)?).to_bytes());
            validate(&k,&p)?;
            let tested=if req.action=="add-device" {
                emit(json!({"event":"new_device_test"}));let _=frame()?;
                unwrap_payload(&k,None,req.new_device.as_ref())?
            } else if req.action=="set-recovery" {
                unwrap_payload(&k,req.new_passphrase.as_ref(),None)?
            } else {
                // The authorizing channel must survive revocation. It was actually
                // decrypted above; do not consume a second PIN attempt unnecessarily.
                if req.passphrase.is_some() {
                    if k.body.recovery.is_none(){return Err("Authenticate with a surviving YubiKey".into());}
                } else {
                    let d=derive_device(req.device.clone().ok_or("Device missing")?)?;
                    if !k.body.devices.iter().any(|v|v.public_key==d.public_key && v.serial==d.serial && v.slot==d.slot){return Err("Authenticate with a surviving unlock method".into());}
                }
                Payload{uuid:p.uuid.clone(),password:p.password.clone(),signing_seed:p.signing_seed.clone(),metadata_identity:p.metadata_identity.clone()}
            };
            if tested.password!=p.password || tested.signing_seed!=p.signing_seed || tested.metadata_identity!=p.metadata_identity {return Err("Independent unlock failed".into());}
            replace_keyring(&req.root,&k,&p,&original)?;
            let mut info=storage::summary(&k,&req.root)?;info["event"]=json!("result");info["independent_unlock_tested"]=json!(true);emit(info);
        },
        "restore-revision"=>{
            let (mut k,p)=prepared.take().ok_or("Restore requires prepared authentication")?;
            let original=read_bounded(&req.root.join(".yka-key"))?;
            k.body.generation=k.body.generation.max(req.restore_generation).checked_add(1).ok_or("Generation limit")?;
            k.signature=B64.encode(key(&p)?.sign(&serde_json::to_vec(&k.body)?).to_bytes());
            replace_keyring(&req.root,&k,&p,&original)?;
            let mut info=storage::summary(&k,&req.root)?;info["event"]=json!("result");emit(info);
        },
        "verify"=>{let (k,_)=unlock(&req)?;let mut info=storage::summary(&k,&req.root)?;info["event"]=json!("result");emit(info);},
        "sign"=>{let (k,p)=match prepared.take(){Some(value)=>value,None=>unlock(&req)?};let message=B64.decode(&req.message)?;
            stage("archive_sign");
            emit(json!({"event":"result","signature":B64.encode(key(&p)?.sign(&message).to_bytes()),"signing_public":k.body.signing_public}));},
        _=>return Err("Unsupported native operation".into()),
    }Ok(())
}
fn main(){
    // Process PATH is controlled by the trusted worker; argv never carries secrets.
    let result=(||->Result<()>{let raw=frame()?;let req:Request=serde_json::from_str(&raw)?;
        drop(raw); // Do not retain the initial credential frame throughout a mounted session.
        // Only this supervisor owns the inherited lease. SecureFS and age-plugin
        // must not retain it after the supervisor exits or is killed.
        #[cfg(windows)] {
            #[link(name="kernel32")]
            extern "system" { fn SetHandleInformation(handle: usize, mask: u32, flags: u32) -> i32; }
            for handle in &req.guard_handles {
                if unsafe { SetHandleInformation(*handle, 1, 0) } == 0 {
                    return Err("Could not protect supervisor lease".into());
                }
            }
        }
        execute(req)})();
    if let Err(error)=result {
        // Whitelist user-facing explanations; never forward raw backend/plugin output.
        let reason=error.to_string();
        let auth_error=error.downcast_ref::<AuthFailure>();
        let current_stage=STAGE.with(|s|s.get());
        let message=if let Some(failure)=auth_error { failure.message() }
        else if reason.contains("identity changed") || reason.contains("identity mismatch") || reason.contains("Untrusted volume") {
            "The vault identity does not match."
        } else if reason.contains("Current password required") {
            "Enter your current password to change it."
        } else if reason.contains("last unlock method") || reason.contains("surviving") {
            "Use another working unlock method."
        } else if reason.contains("already authorized") {
            "This key is already authorized."
        } else if reason.contains("not authorized") {
            "This key is not authorized for this vault."
        } else if reason.contains("Mount target already occupied") {
            "The mount location is in use."
        } else if reason.contains("Keyring changed") || reason.contains("metadata changed") {
            "Vault metadata changed. Try again."
        } else if current_stage=="securefs_unmount" {
            "The vault could not be unmounted. Close files using it and try again."
        } else if current_stage=="securefs_mount" && error_code(&reason)=="backend_timeout" {
            "The mount did not become ready in time. Check its status before trying again."
        } else if matches!(current_stage,"securefs_create"|"securefs_mount") {
            "SecureFS could not start. See Diagnostics for details."
        } else {
            "The operation failed. See Diagnostics for details."
        };
        emit(json!({"event":"error","message":message,"code":auth_error.map_or_else(||error_code(&reason),AuthFailure::code),"stage":current_stage}));std::process::exit(1);
    }
}
