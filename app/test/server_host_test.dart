import 'package:flutter_test/flutter_test.dart';
import 'package:app/services/server_host.dart';

void main() {
  group('requiresAttestation', () {
    test('mainnet demands attestation', () {
      expect(requiresAttestation('mainnet.vtxos.network'), isTrue);
    });

    test('mutinynet is waived — no enclave fronts it yet', () {
      expect(requiresAttestation('mutiny.vtxos.network'), isFalse);
    });

    test('local dev addresses are waived', () {
      for (final h in ['127.0.0.1', 'localhost', '10.0.2.2', '192.168.1.42']) {
        expect(requiresAttestation(h), isFalse, reason: h);
      }
    });

    /// The whole point of spelling the rule as a waiver list. If this ever
    /// inverts to "attest only when host == mainnet", every case below silently
    /// downgrades to unattested plain REST against an arbitrary server.
    test('unknown hosts fail closed', () {
      for (final h in [
        'evil.example.com',
        'mainnet.vtxos.network.evil.com', // suffix-smuggling
        'evilmainnet.vtxos.network', // prefix-smuggling
        'MAINNET.VTXOS.NETWORK', // case variant is not the known-good host
        'mutiny.vtxos.network.evil.com',
        '',
        '10.0.2.3', // adjacent to the emulator alias, not it
        '192.168', // prefix of the local rule but not a host in it
      ]) {
        expect(requiresAttestation(h), isTrue, reason: h);
      }
    });
  });

  group('hostBaseUrl', () {
    test('local hosts get plain HTTP on the runtime port', () {
      expect(hostBaseUrl('10.0.2.2'), 'http://10.0.2.2:7074');
      expect(hostBaseUrl('127.0.0.1'), 'http://127.0.0.1:7074');
      expect(hostBaseUrl('192.168.1.5'), 'http://192.168.1.5:7074');
    });

    test('remote hosts get HTTPS whether or not they are attested', () {
      expect(hostBaseUrl('mainnet.vtxos.network'), 'https://mainnet.vtxos.network');
      // Waived from attestation, but still TLS — the two rules are independent.
      expect(hostBaseUrl('mutiny.vtxos.network'), 'https://mutiny.vtxos.network');
    });
  });

  group('cosignerEndpoint', () {
    test('local dev is plaintext gRPC on 7075', () {
      final e = cosignerEndpoint('127.0.0.1');
      expect(e.host, '127.0.0.1');
      expect(e.port, 7075);
      expect(e.secure, isFalse);
    });

    /// 443 and TLS, terminated by whatever fronts the guest — the component has
    /// no listener and no certificate of its own.
    test('remote is TLS on 443', () {
      final e = cosignerEndpoint('mainnet.vtxos.network');
      expect(e.port, 443);
      expect(e.secure, isTrue);
    });
  });

  group('aspEndpoint', () {
    test('local dev points at the regtest arkd beside the cosigner', () {
      final e = aspEndpoint('10.0.2.2');
      expect(e.host, '10.0.2.2');
      expect(e.port, 7070);
      expect(e.secure, isFalse);
    });

    test('mutinynet has its own ASP, not the cosigner host', () {
      final e = aspEndpoint('mutiny.vtxos.network');
      expect(e.host, 'mutinynet.arkade.sh');
      expect(e.secure, isTrue);
    });

    /// An unconfigured host must fail loudly rather than default. The cosigner
    /// derives every output it signs from the ASP's signer key, so the wrong ASP
    /// does not redirect funds — it produces a wallet that reads as empty, which
    /// is a far more confusing way to find out.
    test('an unknown host is refused rather than guessed', () {
      expect(() => aspEndpoint('mainnet.vtxos.network'), throwsStateError);
    });
  });

  group('isLocalHost', () {
    test('does not treat remote deployments as local', () {
      expect(isLocalHost('mutiny.vtxos.network'), isFalse);
      expect(isLocalHost('mainnet.vtxos.network'), isFalse);
    });
  });
}
