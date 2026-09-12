//! Merlin regtest REPL — a scriptable wallet for driving the cosigner end to end.
//!
//! Holds several named wallets in one process (`use <name>` switches the active identity), so both
//! sides of a payment request can be driven from a single session.
//!
//! Point it at a running runtime with `COSIGNER_URL` (default `http://127.0.0.1:7074`).
//! Regtest only — the keystore holds signing secrets in plaintext.

mod bitcoin;
mod client;
mod keystore;
mod onboarding;
mod session;
mod signing;

use std::io::{self, BufRead, Write};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use client::{signer_from_key_package, Client};
use keystore::Keystore;

const HELP: &str = "\
commands
  wallets                         list wallets in the keystore
  new <name>                      onboard a new wallet (2-of-2 DKG with the cosigner)
  use <name>                      switch the active wallet
  whoami                          show the active wallet's ids

  balance                         spendable VTXO total
  receive                         this wallet's Ark address
  history                         Ark transaction history
  fund <sats>                     regtest-only: fund + board in one step (needs bitcoind)
  boarding-address                on-chain address to fund, then `board`
  board <txid> <vout> <sats>      settle a funded boarding UTXO into VTXOs
  send <ark_address> <sats>       off-chain Ark send (2-of-2 FROST)

  contacts                        who may bill this wallet
  contact-add <name|vk_hex> [label]
  contact-rm  <name|vk_hex>

  request <payer> <sats> [memo]   ask <payer> to pay THIS wallet
  requests                        payment requests addressed to this wallet
  approve <id>                    pay a request (amount + payee come from the stored intent)
  decline <id>                    decline a request

  help | quit
";

#[tokio::main]
async fn main() -> Result<()> {
    let base = std::env::var("COSIGNER_URL").unwrap_or_else(|_| "http://127.0.0.1:7074".to_string());
    let client = Client::new(base.clone());
    let mut ks = Keystore::load()?;

    println!("merlin regtest REPL → {base}");
    println!(
        "keystore {} (PLAINTEXT SECRETS — regtest only)",
        Keystore::path()?.display()
    );
    println!("type `help`\n");

    // A real line editor: handles bracketed paste (a pasted group key arrives intact), plus
    // arrow-key editing and history. Falls back to plain stdin when there's no TTY.
    let mut rl = match rustyline::DefaultEditor::new() {
        Ok(rl) => rl,
        Err(e) => {
            eprintln!("line editor unavailable ({e}); falling back to plain stdin");
            return run_plain(&client, &mut ks).await;
        }
    };
    loop {
        let prompt = ks
            .active()
            .map(|(n, _)| format!("{n}> "))
            .unwrap_or_else(|| "(no wallet)> ".to_string());

        match rl.readline(&prompt) {
            Ok(raw) => {
                let line = raw.trim();
                if line.is_empty() {
                    continue;
                }
                if matches!(line, "quit" | "exit") {
                    break;
                }
                let _ = rl.add_history_entry(line);
                if let Err(e) = dispatch(line, &client, &mut ks).await {
                    eprintln!("error: {e:#}");
                }
            }
            // Ctrl-C clears the current line; Ctrl-D / EOF exits.
            Err(rustyline::error::ReadlineError::Interrupted) => continue,
            Err(rustyline::error::ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("input error: {e}");
                break;
            }
        }
    }
    Ok(())
}

/// Fallback REPL over plain stdin (no TTY — e.g. piped input in scripts/tests).
async fn run_plain(client: &Client, ks: &mut Keystore) -> Result<()> {
    let stdin = io::stdin();
    loop {
        let prompt = ks
            .active()
            .map(|(n, _)| format!("{n}> "))
            .unwrap_or_else(|| "(no wallet)> ".to_string());
        print!("{prompt}");
        io::stdout().flush().ok();

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            println!();
            break; // EOF
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if matches!(line, "quit" | "exit") {
            break;
        }
        if let Err(e) = dispatch(line, client, ks).await {
            eprintln!("error: {e:#}");
        }
    }
    Ok(())
}

async fn dispatch(line: &str, client: &Client, ks: &mut Keystore) -> Result<()> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    let args: Vec<&str> = parts.collect();

    match cmd {
        "help" => println!("{HELP}"),

        "wallets" => {
            if ks.wallets.is_empty() {
                println!("(none — `new <name>` to onboard one)");
            }
            for (name, w) in &ks.wallets {
                let marker = if ks.active.as_deref() == Some(name.as_str()) {
                    "*"
                } else {
                    " "
                };
                println!("{marker} {name:<12} group={}  id={}", w.group_key, w.user_id_hex);
            }
        }

        "new" => {
            let name = args
                .first()
                .ok_or_else(|| anyhow!("usage: new <name>"))?
                .to_string();
            if ks.wallets.contains_key(&name) {
                return Err(anyhow!("wallet `{name}` already exists"));
            }
            println!("running 2-of-2 DKG with the cosigner…");
            let wallet = onboarding::onboard(client).await?;
            println!("  group key {}", wallet.group_key);
            println!("  auth id   {}", wallet.user_id_hex);
            ks.wallets.insert(name.clone(), wallet);
            ks.active = Some(name.clone());
            ks.save()?;
            println!("wallet `{name}` created and selected");
        }

        "use" => {
            let name = args.first().ok_or_else(|| anyhow!("usage: use <name>"))?;
            if !ks.wallets.contains_key(*name) {
                return Err(anyhow!("no wallet `{name}`"));
            }
            ks.active = Some((*name).to_string());
            ks.save()?;
        }

        "whoami" => {
            let (name, w) = active(ks)?;
            println!("{name}");
            println!("  group key {}   (identity — allowlist THIS to let it bill you)", w.group_key);
            println!("  auth id   {}   (share key; signs sign/* and contacts/*)", w.user_id_hex);
        }

        "balance" => {
            let (_, w) = active(ks)?;
            let resp = client
                .post_session(&w.group_key, "/ark/vtxos", json!({}))
                .await?;
            let vtxos = resp.get("vtxos").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let total = resp
                .get("total_balance")
                .and_then(|v| v.as_u64())
                .unwrap_or_default();
            println!("{total} sats across {} vtxo(s)", vtxos.len());
        }

        "receive" => {
            let (_, w) = active(ks)?;
            let resp = client
                .post_session(&w.group_key, "/ark/address", json!({}))
                .await?;
            println!("{}", resp.get("ark_address").and_then(|v| v.as_str()).unwrap_or("(none)"));
        }

        "history" => {
            let (_, w) = active(ks)?;
            let resp = client
                .post_session(&w.group_key, "/ark/transactions", json!({}))
                .await?;
            let txs = resp.get("transactions").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if txs.is_empty() {
                println!("(no transactions)");
            }
            for t in txs {
                println!(
                    "{:<8} {:>12}  {}",
                    t.get("tx_type").and_then(|v| v.as_str()).unwrap_or("?"),
                    t.get("amount_sats").and_then(|v| v.as_i64()).unwrap_or(0),
                    t.get("txid").and_then(|v| v.as_str()).unwrap_or("")
                );
            }
        }

        "fund" => {
            // Regtest convenience: boarding address -> pay -> confirm -> find UTXO -> board.
            let sats: u64 = args
                .first()
                .ok_or_else(|| anyhow!("usage: fund <sats>"))?
                .parse()
                .map_err(|_| anyhow!("bad amount"))?;
            let (_, w) = active(ks)?;
            let group_key = w.group_key.clone();

            let addr_resp = client
                .post_session(&group_key, "/ark/boarding-address", json!({}))
                .await?;
            let addr = addr_resp
                .get("boarding_address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("no boarding address"))?
                .to_string();
            println!("boarding address {addr}");

            let btc = bitcoin::BitcoinRpc::from_env();
            let txid = btc.send_to(&addr, sats).await?;
            println!("funded + confirmed: {txid}");
            let (vout, utxo_sats) = btc.find_output(&txid, &addr).await?;

            println!("boarding {utxo_sats} sats (drives the batch; may take a few rounds)…");
            let commitment = signing::settle_boarding(client, w, (txid, vout, utxo_sats)).await?;
            println!("boarded — commitment {commitment}
  run `balance` to see the VTXO");
        }

        "boarding-address" => {
            let (_, w) = active(ks)?;
            let resp = client
                .post_session(&w.group_key, "/ark/boarding-address", json!({}),
                )
                .await?;
            println!("{}", resp.get("boarding_address").and_then(|v| v.as_str()).unwrap_or("(none)"));
            println!("fund it on-chain, wait for a confirmation, then run `board`");
        }

        "board" => {
            if args.len() < 3 {
                return Err(anyhow!(
                    "usage: board <txid> <vout> <sats>\n\
                     (the cosigner does not scan the chain — supply the boarding UTXO you funded)"
                ));
            }
            let txid = args[0].to_string();
            let vout: u32 = args[1].parse().map_err(|_| anyhow!("bad vout"))?;
            let sats: u64 = args[2].parse().map_err(|_| anyhow!("bad amount"))?;
            let (_, w) = active(ks)?;
            println!("settling boarding UTXO (drives the batch; may take a few rounds)…");
            let commitment = signing::settle_boarding(client, w, (txid, vout, sats)).await?;
            println!("boarded — commitment {commitment}");
        }

        "send" => {
            if args.len() < 2 {
                return Err(anyhow!("usage: send <ark_address> <sats>"));
            }
            let to = args[0].to_string();
            let sats: u64 = args[1].parse().map_err(|_| anyhow!("bad amount"))?;
            let (_, w) = active(ks)?;
            let txid = signing::send_vtxo(client, w, &to, sats).await?;
            println!("sent {sats} sats → {to}\n  ark txid {txid}");
        }

        "approve" => {
            let id = args.first().ok_or_else(|| anyhow!("usage: approve <id>"))?;
            let (_, w) = active(ks)?;
            let signer = signer_from_key_package(&w.key_package_json)?;
            // Pay from the STORED intent, never anything typed here — the seal is the authority
            // on payee + amount, and the cosigner matches on it to mark the request fulfilled.
            let list = client
                .post_signed(&w.group_key, "/payment-request/list", "PAYREQ_LIST", &signer, json!({}))
                .await?;
            let intent = list
                .get("intents")
                .and_then(|v| v.as_array())
                .and_then(|a| {
                    a.iter()
                        .find(|i| i.get("id").and_then(|v| v.as_str()) == Some(*id))
                        .cloned()
                })
                .ok_or_else(|| anyhow!("no request `{id}` in this wallet's inbox"))?;

            let status = intent.get("status").and_then(|v| v.as_str()).unwrap_or("");
            if status != "pending" {
                return Err(anyhow!("request is {status}, not pending"));
            }
            let to = intent
                .get("to_ark_address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("intent has no payee address"))?
                .to_string();
            let sats = intent.get("amount_sats").and_then(|v| v.as_u64()).unwrap_or(0);

            println!("paying {sats} sats to {to} …");
            let txid = signing::send_vtxo(client, w, &to, sats).await?;
            println!("paid — ark txid {txid}");
            println!("(the cosigner marks the request fulfilled by matching payee + amount)");
        }

        "contacts" => {
            let (_, w) = active(ks)?;
            let signer = signer_from_key_package(&w.key_package_json)?;
            let resp = client
                .post_signed(&w.group_key, "/contacts/list", "CONTACT_LIST", &signer, json!({}))
                .await?;
            let contacts = resp.get("contacts").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if contacts.is_empty() {
                println!("(nobody may bill this wallet)");
            }
            for c in contacts {
                println!(
                    "{:<16} {}",
                    c.get("label").and_then(|v| v.as_str()).unwrap_or(""),
                    bytes_hex(&c, "verifying_key")
                );
            }
        }

        "contact-add" => {
            let who = args.first().ok_or_else(|| anyhow!("usage: contact-add <name|vk_hex> [label]"))?;
            // A contact is identified by its GROUP key.
            let vk = ks.resolve_group_key(who);
            let label = if args.len() > 1 { args[1..].join(" ") } else { (*who).to_string() };
            let (_, w) = active(ks)?;
            let signer = signer_from_key_package(&w.key_package_json)?;
            client
                .post_signed(
                    &w.group_key,
                    "/contacts/add",
                    "CONTACT_ADD",
                    &signer,
                    json!({ "contact_verifying_key": vk, "label": label }),
                )
                .await?;
            println!("{label} ({vk}) may now bill this wallet");
        }

        "contact-rm" => {
            let who = args.first().ok_or_else(|| anyhow!("usage: contact-rm <name|vk_hex>"))?;
            let vk = ks.resolve_group_key(who);
            let (_, w) = active(ks)?;
            let signer = signer_from_key_package(&w.key_package_json)?;
            client
                .post_signed(
                    &w.group_key,
                    "/contacts/remove",
                    "CONTACT_REMOVE",
                    &signer,
                    json!({ "contact_verifying_key": vk }),
                )
                .await?;
            println!("{vk} revoked (their pending requests are dropped too)");
        }

        "request" => {
            if args.len() < 2 {
                return Err(anyhow!("usage: request <payer> <sats> [memo]"));
            }
            let payer_group = ks.resolve_group_key(args[0]);
            let sats: u64 = args[1].parse().map_err(|_| anyhow!("bad amount"))?;
            let memo = if args.len() > 2 { args[2..].join(" ") } else { String::new() };
            let (_, w) = active(ks)?;
            // Cross-wallet: URL = the PAYER's actor, identity = OUR GROUP key (the cosigner
            // derives our payee address from it).
            let resp = client
                .post_as_group(
                    &payer_group,
                    "/payment-request/create",
                    &w.group_key,
                    json!({ "amount_sats": sats, "memo": memo }),
                )
                .await?;
            let intent = resp.get("intent").cloned().unwrap_or(json!({}));
            println!(
                "requested {sats} sats from {payer_group}\n  id      {}\n  payable to {}",
                intent.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
                intent.get("to_ark_address").and_then(|v| v.as_str()).unwrap_or("?")
            );
        }

        "requests" => {
            let (_, w) = active(ks)?;
            let signer = signer_from_key_package(&w.key_package_json)?;
            let resp = client
                .post_signed(&w.group_key, "/payment-request/list", "PAYREQ_LIST", &signer, json!({}))
                .await?;
            let intents = resp.get("intents").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if intents.is_empty() {
                println!("(no payment requests)");
            }
            for i in intents {
                println!(
                    "{:<32} {:>10} sats  {:<9} from {}  {}",
                    i.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                    i.get("amount_sats").and_then(|v| v.as_u64()).unwrap_or(0),
                    i.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                    bytes_hex(&i, "from_verifying_key"),
                    i.get("memo").and_then(|v| v.as_str()).unwrap_or("")
                );
            }
        }

        "decline" => {
            let id = args.first().ok_or_else(|| anyhow!("usage: decline <id>"))?;
            let (_, w) = active(ks)?;
            let signer = signer_from_key_package(&w.key_package_json)?;
            client
                .post_signed(
                    &w.group_key,
                    "/payment-request/decline",
                    "PAYREQ_DECLINE",
                    &signer,
                    json!({ "id": id }),
                )
                .await?;
            println!("declined {id}");
        }

        other => println!("unknown command `{other}` — try `help`"),
    }
    Ok(())
}

/// Read a proto `bytes` field as hex. `dispatch_json!` responses serialize prost `Vec<u8>` as a
/// JSON array of numbers, while hand-built responses use hex — accept both.
fn bytes_hex(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => hex::encode(
            a.iter()
                .filter_map(|n| n.as_u64().map(|b| b as u8))
                .collect::<Vec<u8>>(),
        ),
        _ => String::new(),
    }
}

fn active(ks: &Keystore) -> Result<(&str, &keystore::Wallet)> {
    ks.active()
        .ok_or_else(|| anyhow!("no active wallet — `new <name>` or `use <name>`"))
}
