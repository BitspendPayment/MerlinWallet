//! arkd's REST gateway JSON, into the prost types the Ark session code already consumes.
//!
//! The gateway is protobuf's JSON mapping: camelCase names, and 64-bit integers as strings. Read
//! through `serde_json::Value` rather than derived structs, so a number that arrives as a number
//! instead of a string — gateways disagree — reads the same.

use std::collections::HashMap;

use ark::client::proto::{
    get_event_stream_response::Event, BatchFailedEvent, BatchFinalizationEvent,
    BatchFinalizedEvent, BatchStartedEvent, Heartbeat, StreamStartedEvent, TreeNoncesAggregatedEvent,
    TreeNoncesEvent, TreeSignatureEvent, TreeSigningStartedEvent, TreeTxEvent,
};
use ark::client::types::ArkInfo;
use serde_json::Value;

/// One event payload off the stream. `Ok(None)` for a message that carries no event.
///
/// Accepts the event object itself or the gateway's streaming envelope, `{"result": {...}}`; an
/// `{"error": ...}` envelope is the stream failing and is returned as one.
pub fn event(payload: &str) -> Result<Option<Event>, String> {
    let value: Value =
        serde_json::from_str(payload).map_err(|e| format!("ASP event is not JSON: {e}"))?;
    if let Some(error) = value.get("error") {
        return Err(format!("ASP event stream failed: {error}"));
    }
    let v = value.get("result").unwrap_or(&value);

    let text = |o: &Value, k: &str| o.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let strings = |o: &Value, k: &str| -> Vec<String> {
        o.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let map = |o: &Value, k: &str| -> HashMap<String, String> {
        o.get(k)
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };

    Ok(Some(if let Some(e) = v.get("batchStarted") {
        Event::BatchStarted(BatchStartedEvent {
            id: text(e, "id"),
            intent_id_hashes: strings(e, "intentIdHashes"),
            batch_expiry: int(e, "batchExpiry")?,
        })
    } else if let Some(e) = v.get("batchFinalization") {
        Event::BatchFinalization(BatchFinalizationEvent {
            id: text(e, "id"),
            commitment_tx: text(e, "commitmentTx"),
        })
    } else if let Some(e) = v.get("batchFinalized") {
        Event::BatchFinalized(BatchFinalizedEvent {
            id: text(e, "id"),
            commitment_txid: text(e, "commitmentTxid"),
        })
    } else if let Some(e) = v.get("batchFailed") {
        Event::BatchFailed(BatchFailedEvent {
            id: text(e, "id"),
            reason: text(e, "reason"),
        })
    } else if let Some(e) = v.get("treeSigningStarted") {
        Event::TreeSigningStarted(TreeSigningStartedEvent {
            id: text(e, "id"),
            cosigners_pubkeys: strings(e, "cosignersPubkeys"),
            unsigned_commitment_tx: text(e, "unsignedCommitmentTx"),
        })
    } else if let Some(e) = v.get("treeNoncesAggregated") {
        Event::TreeNoncesAggregated(TreeNoncesAggregatedEvent {
            id: text(e, "id"),
            tree_nonces: map(e, "treeNonces"),
        })
    } else if let Some(e) = v.get("treeTx") {
        let children = e
            .get("children")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| Some((k.parse::<u32>().ok()?, v.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        Event::TreeTx(TreeTxEvent {
            id: text(e, "id"),
            topic: strings(e, "topic"),
            batch_index: int(e, "batchIndex")? as i32,
            txid: text(e, "txid"),
            tx: text(e, "tx"),
            children,
        })
    } else if let Some(e) = v.get("treeSignature") {
        Event::TreeSignature(TreeSignatureEvent {
            id: text(e, "id"),
            topic: strings(e, "topic"),
            batch_index: int(e, "batchIndex")? as i32,
            txid: text(e, "txid"),
            signature: text(e, "signature"),
        })
    } else if let Some(e) = v.get("treeNonces") {
        Event::TreeNonces(TreeNoncesEvent {
            id: text(e, "id"),
            topic: strings(e, "topic"),
            txid: text(e, "txid"),
            nonces: map(e, "nonces"),
        })
    } else if v.get("heartbeat").is_some() {
        Event::Heartbeat(Heartbeat {})
    } else if let Some(e) = v.get("streamStarted") {
        Event::StreamStarted(StreamStartedEvent { id: text(e, "id") })
    } else {
        return Ok(None);
    }))
}

/// `GET /v1/info`, as the session code's `ArkInfo`.
pub fn ark_info(body: &str) -> Result<ArkInfo, String> {
    let v: Value = serde_json::from_str(body).map_err(|e| format!("ASP info is not JSON: {e}"))?;
    let text = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("ASP info has no {k}"))
    };
    Ok(ArkInfo {
        signer_pubkey: text("signerPubkey")?,
        forfeit_pubkey: text("forfeitPubkey")?,
        forfeit_address: text("forfeitAddress")?,
        checkpoint_tapscript: text("checkpointTapscript")?,
        network: text("network")?,
        session_duration: int(&v, "sessionDuration")?,
        unilateral_exit_delay: int(&v, "unilateralExitDelay")?,
        boarding_exit_delay: int(&v, "boardingExitDelay")?,
        vtxo_min_amount: int(&v, "vtxoMinAmount")?,
        dust: int(&v, "dust")?,
    })
}

/// An integer field, as a JSON string or number; 0 when absent, as protobuf's JSON mapping omits
/// zero values.
fn int(o: &Value, k: &str) -> Result<i64, String> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n.as_i64().ok_or_else(|| format!("{k} is not an integer")),
        Some(Value::String(s)) => s.parse().map_err(|_| format!("{k} is not an integer: {s:?}")),
        Some(other) => Err(format!("{k} is not an integer: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_read_from_the_gateway_json() {
        let e = event(r#"{"result":{"batchStarted":{"id":"b1","intentIdHashes":["h"],"batchExpiry":"512"}}}"#)
            .unwrap()
            .unwrap();
        let Event::BatchStarted(b) = e else { panic!("{e:?}") };
        assert_eq!((b.id.as_str(), b.batch_expiry, b.intent_id_hashes.len()), ("b1", 512, 1));

        let e = event(r#"{"treeTx":{"id":"b1","topic":["t"],"batchIndex":1,"txid":"x","tx":"psbt","children":{"0":"c0","1":"c1"}}}"#)
            .unwrap()
            .unwrap();
        let Event::TreeTx(t) = e else { panic!("{e:?}") };
        assert_eq!(t.batch_index, 1);
        assert_eq!(t.children.get(&1).map(String::as_str), Some("c1"));

        assert!(matches!(event(r#"{"heartbeat":{}}"#).unwrap(), Some(Event::Heartbeat(_))));
        assert!(event(r#"{"somethingNew":{}}"#).unwrap().is_none());
        assert!(event(r#"{"error":{"code":14,"message":"gone"}}"#).is_err());
    }

    /// The arkd in docker-compose.ark.yml answered `/v1/info` with exactly these fields.
    #[test]
    fn info_reads_from_the_gateway_json() {
        let info = ark_info(r#"{"version":"v0.9.2","signerPubkey":"02e3","forfeitPubkey":"03dd","forfeitAddress":"bcrt1q","checkpointTapscript":"5ab2","network":"regtest","sessionDuration":"10","unilateralExitDelay":"86016","boardingExitDelay":"172032","vtxoMinAmount":"1","dust":"330"}"#)
            .unwrap();
        assert_eq!(info.network, "regtest");
        assert_eq!(info.unilateral_exit_delay, 86016);
        assert_eq!(info.dust, 330);
    }
}
