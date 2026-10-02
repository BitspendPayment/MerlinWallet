//! Pairing a service into an escrow this cosigner holds: the service ([`Service`]), the escrow's
//! key material ([`EscrowDetails`]), and the dealing and delivery between them.

use std::sync::{Arc, Mutex};

use threshold::identifier::Identifier;
use threshold::keys::{KeyPackage, PublicKeyPackage};

use crate::cosigner::Cosigner;
use crate::grpc::Status;
use crate::session::{lock, proto};

/// One escrow, as this cosigner holds it — see [`Cosigner::escrow_details`].
pub(crate) struct EscrowDetails {
    /// `V'`, compressed hex.
    pub(crate) key: String,
    /// This cosigner's share of `V'`.
    pub(crate) key_package: KeyPackage,
    /// The escrow's public package.
    pub(crate) public_key_package: PublicKeyPackage,
    /// The wallet's identifier in it.
    pub(crate) wallet_id: Identifier,
}

impl EscrowDetails {
    /// Deal this cosigner's half of a pairing from the wallet's dealing, hand it to the service,
    /// and seal the pairing pending. What comes back tells the wallet where to send its own half.
    ///
    /// Deliver, then seal, as [`crate::handlers::delivery`] explains: this cosigner never keeps the
    /// service's half, so a pairing sealed before a failed delivery could never be completed.
    pub(crate) async fn deal_and_deliver(
        &self,
        cosigner: &Arc<Mutex<Cosigner>>,
        service: &Service,
        attempt_id_hex: &str,
        deal: proto::PairServiceDeal,
    ) -> Result<proto::PairServiceDone, Status> {
        let material = crate::handlers::pairing::pair_service(
            &self.key_package,
            &self.public_key_package,
            &self.wallet_id,
            &service.id,
            &deal.contribution_to_cosigner,
            &deal.contribution_to_service,
        )?;
        // Over the connection the runtime will go on holding after this call ends — that is what
        // lets the service speak first later, when it asks for a release. See `handlers::delivery`.
        let host = lock(cosigner).host();
        crate::handlers::delivery::deliver_pairing_half(
            host.as_ref(),
            &material.service_identifier_hex,
            &service.origin,
            &crate::service_stream::ToService::PairingHalf {
                escrow_key: self.key.clone(),
                attempt_id: attempt_id_hex.to_string(),
                service_identifier: material.service_identifier_hex.clone(),
                half: hex::encode(&material.service_half),
                public_key_package_json: material.public_key_package_json.clone(),
                service_verifying_share: material.service_verifying_share_hex.clone(),
            },
        )
        .await
        .map_err(|e| {
            Status::unavailable(format!(
                "the service did not take its half, so nothing was paired: {e}"
            ))
        })?;

        let done = proto::PairServiceDone {
            public_key_package_json: material.public_key_package_json.clone(),
            service_verifying_share: material.service_verifying_share_hex.clone(),
            // So the wallet delivers its own half to the same place. It does not choose an
            // origin, and could not: the list lives in the image.
            service_origin: service.origin.clone(),
        };
        let mut c = lock(cosigner);
        c.pair_escrow_service(
            &self.key,
            crate::types::ServicePairing {
                service_identifier_hex: material.service_identifier_hex,
                key_package_json: material.key_package_json,
                public_key_package_json: material.public_key_package_json,
                service_verifying_share_hex: material.service_verifying_share_hex,
                paired_at: crate::handlers::helpers::now_secs(),
                attempt_id_hex: attempt_id_hex.to_string(),
                // Delivered, not yet shown to work: the service has one half of two, and neither
                // party has vouched for it. See `handlers::delivery`.
                service_confirmed: false,
                wallet_confirmed: false,
            },
        )
        .map_err(Status::failed_precondition)?;
        c.seal();
        Ok(done)
    }
}

/// A service to pair into an escrow: who it is, and where the image says it is.
pub(crate) struct Service {
    id: Identifier,
    origin: String,
}

impl Service {
    /// The service [identifier] names, checked before anything is dealt.
    pub(crate) fn named(identifier: &[u8]) -> Result<Self, Status> {
        // Where this service is, according to the IMAGE. Resolved before anything is dealt, so
        // naming a service this enclave does not know costs nothing and reveals nothing.
        let origin = crate::handlers::delivery::ServiceRegistry::from_env()
            .origin_of(&hex::encode(identifier))?
            .to_string();
        let id = Identifier::try_from(identifier)
            .map_err(|e| Status::invalid_argument(format!("bad service identifier: {e}")))?;
        Ok(Self { id, origin })
    }
}
