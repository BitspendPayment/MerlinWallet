/// Handing a service the wallet's half of a pairing.
///
/// A pairing has two contributions and they travel by **different routes**, on purpose:
///
/// ```text
///   cosigner ──b@service──▶ service       from inside the enclave
///   wallet   ──a@service──▶ service       from this device, to the SAME origin
///                            └── s = a + b, checked against the published verifying share
/// ```
///
/// The wallet's half must not go through the cosigner. That cosigner already holds its own
/// counter-share in the pairing; one that also saw `a@service` would hold both terms of the
/// service's share and could sign as the service. So the two halves never meet anywhere except at
/// the service that needs them.
///
/// **The wallet does not choose where to send.** The origin comes back from the cosigner
/// (`PairServiceDone.service_origin`), which resolved it from `SERVICE_ORIGINS` in its measured
/// image — so both halves go to the same host, and the host is one a client can verify from the
/// attestation rather than one this device picked.
///
/// What is sent is a secret: `a@service` is one term of the service's signing share. It is sent to
/// exactly one place, over TLS, and nothing else about this wallet goes with it — not its own
/// share, not its passkey, not the escrow's other half.
library;

import 'dart:convert';
import 'dart:io';

/// One wallet contribution, labelled so the service knows what it belongs to.
class ServiceContribution {
  const ServiceContribution({
    required this.escrowKeyHex,
    required this.attemptIdHex,
    required this.serviceIdentifierHex,
    required this.contributionHex,
  });

  final String escrowKeyHex;

  /// Which attempt. The cosigner's half carries the same label — that is what tells the service
  /// which two halves belong together, and keeps a retry's halves apart from an abandoned one's.
  final String attemptIdHex;
  final String serviceIdentifierHex;

  /// `a@service`, a 32-byte scalar as hex. **Secret**: one term of the service's share.
  final String contributionHex;

  Map<String, dynamic> toJson() => {
        'escrow_key': escrowKeyHex,
        'attempt_id': attemptIdHex,
        'service_identifier': serviceIdentifierHex,
        'contribution': contributionHex,
      };
}

/// Why a contribution did not arrive. Distinguished because they call for different things: a
/// refusal is final for this attempt, and a transport failure is worth retrying.
class ServiceDeliveryException implements Exception {
  ServiceDeliveryException(this.message, {this.refused = false});

  final String message;

  /// The service answered and said no. Retrying the same attempt will get the same answer.
  final bool refused;

  @override
  String toString() => message;
}

/// Sending one contribution to one service.
abstract class DeliverToService {
  /// Idempotent for one attempt: the service keys what it holds by `(escrow, attempt)`, so a
  /// redelivery after a timeout is the same delivery rather than a second one.
  Future<void> deliver(String origin, ServiceContribution contribution);
}

/// Delivery over HTTPS, which is how a device reaches anything.
class HttpServiceDelivery implements DeliverToService {
  HttpServiceDelivery({Duration timeout = const Duration(seconds: 20)}) : _timeout = timeout;

  final Duration _timeout;

  @override
  Future<void> deliver(String origin, ServiceContribution contribution) async {
    final uri = Uri.parse('$origin/pair/wallet');
    // Plain HTTP is refused unless the origin is a loopback or private address — a dev stack is
    // reachable that way and a real service is not. A secret must not leave this device in the
    // clear because a URL happened to say `http`.
    if (uri.scheme != 'https' && !isLocalDevelopmentHost(uri.host)) {
      throw ServiceDeliveryException(
        'refusing to send a pairing contribution to $origin in the clear: it is a secret, and '
        'that host is not a local development address',
        refused: true,
      );
    }

    final client = HttpClient()..connectionTimeout = _timeout;
    try {
      final request = await client.postUrl(uri).timeout(_timeout);
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(contribution.toJson()));
      final response = await request.close().timeout(_timeout);
      final body = await utf8.decodeStream(response);
      if (response.statusCode >= 200 && response.statusCode < 300) return;
      throw ServiceDeliveryException(
        'the service refused this wallet\'s contribution (${response.statusCode}): $body',
        // 4xx is a decision; 5xx and anything else may be transient.
        refused: response.statusCode >= 400 && response.statusCode < 500,
      );
    } on ServiceDeliveryException {
      rethrow;
    } catch (e) {
      throw ServiceDeliveryException('could not reach $origin to deliver a contribution: $e');
    } finally {
      client.close(force: true);
    }
  }

}

/// Whether [host] is somewhere a secret may go in the clear: the loopback, or a private IPv4
/// address, as a dev stack is reached.
///
/// An ADDRESS, never a name. This used to be a prefix test on the string — `10.` — which
/// `10.attacker.com` passes; a name is resolved by whoever answers DNS, and is not a place.
bool isLocalDevelopmentHost(String host) {
  if (host == 'localhost') return true;
  final address = InternetAddress.tryParse(host);
  if (address == null) return false;
  if (address.isLoopback) return true;
  if (address.type != InternetAddressType.IPv4) return false;
  final b = address.rawAddress;
  return b[0] == 10 ||
      (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
      (b[0] == 192 && b[1] == 168);
}

/// Delivery to a service the enclave names by an address this device reaches under another name.
///
/// The cosigner reports the origin it delivered to, and the wallet sends its own half to the same
/// one — which is what keeps the two halves from being split between two hosts. But in a dev stack
/// the enclave and this device do not share a view of the network: `192.168.127.254` is the QEMU
/// host as the guest sees it, while the same host is `127.0.0.1` to a process on it, or to a phone
/// through `adb reverse`. A real service has one public name, and this never applies to it.
///
/// Only that one host is rewritten, and [HttpServiceDelivery] still refuses to send a secret in
/// the clear to anything that is not a local development address.
class RewritingDelivery implements DeliverToService {
  RewritingDelivery({this.guestFacingHost = '192.168.127.254', this.hostFacingHost = '127.0.0.1'});

  final String guestFacingHost;
  final String hostFacingHost;
  final HttpServiceDelivery _inner = HttpServiceDelivery();

  /// Every origin this was asked to deliver to, as the enclave named it.
  final List<String> asked = [];

  @override
  Future<void> deliver(String origin, ServiceContribution contribution) {
    asked.add(origin);
    final uri = Uri.parse(origin);
    final reachable =
        uri.host == guestFacingHost ? uri.replace(host: hostFacingHost).toString() : origin;
    return _inner.deliver(reachable, contribution);
  }
}
