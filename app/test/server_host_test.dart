import 'package:flutter_test/flutter_test.dart';
import 'package:app/services/server_host.dart';

void main() {
  const dev = DevEnclaveConfig(
    port: 8443,
    certificateName: 'enclave.test',
    rpId: 'vtxos.com',
    caPemBase64: '',
    trustRootBase64: 'AAEC',
    pcr0: '8f2026d5a6c50479e27152c06ca86852ce0ec9528efd5f13d8bee969f128076adf1c720ead49d5629724fe2562a1cd99',
    pcr16: 'e5d19028de3519c28511df1942d0bac7ba3e633707adbd3c4017d4ba8ca8e515a1b79e5b91081ec19267cf35f732f9b3',
  );

  group('enclaveEndpoint', () {
    /// The dev enclave listens on loopback with a certificate for its rp id: dial one, verify the
    /// other.
    test('a local host dials the dev enclave port and verifies its certificate name', () {
      final e = enclaveEndpoint('10.0.2.2', dev: dev);
      expect(e.host, '10.0.2.2');
      expect(e.port, 8443);
      expect(e.authority, 'enclave.test');
      expect(e.baseUrl, 'https://enclave.test:8443');
    });

    test('a remote host is itself, on 443', () {
      final e = enclaveEndpoint('mainnet.vtxos.network', dev: dev);
      expect(e.host, 'mainnet.vtxos.network');
      expect(e.authority, 'mainnet.vtxos.network');
      expect(e.port, 443);
      expect(e.baseUrl, 'https://mainnet.vtxos.network');
    });
  });

  group('relying party', () {
    /// The certificate still says enclave.test; the relying party is whatever the image was built
    /// with, which for a phone has to be a domain that vouches for the app.
    test('local is the dev image\'s rp id, independent of its certificate', () {
      expect(relyingPartyId('127.0.0.1', dev: dev), 'vtxos.com');
      expect(origin('127.0.0.1', dev: dev), 'https://vtxos.com');
      expect(enclaveEndpoint('127.0.0.1', dev: dev).authority, 'enclave.test');
    });

    /// The domain whose assetlinks.json names the app — not each deployment's own host, which
    /// publishes none, so a passkey bound to it could never be created on a phone.
    test('every remote deployment shares vtxos.com', () {
      for (final h in ['mutiny.vtxos.network', 'mainnet.vtxos.network']) {
        expect(relyingPartyId(h, dev: dev), 'vtxos.com', reason: h);
        expect(origin(h, dev: dev), 'https://vtxos.com', reason: h);
      }
    });
  });

  group('DevEnclaveConfig', () {
    test('carries the pins it was built with', () {
      final pins = dev.pins();
      expect(pins.pcr0, dev.pcr0);
      expect(pins.pcr16, dev.pcr16);
      expect(pins.trustRoot, [0, 1, 2]);
    });

    /// A build without pins has nothing to hold the enclave to. Refusing is the point.
    test('a build without pins refuses rather than trusting whatever answers', () {
      expect(() => const DevEnclaveConfig().pins(), throwsStateError);
      expect(
        () => DevEnclaveConfig(trustRootBase64: 'AAEC', pcr0: dev.pcr0, pcr16: 'short').pins(),
        throwsStateError,
      );
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
