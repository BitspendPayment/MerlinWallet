/// What a device keeps of an escrow the cosigner lists, and what it refuses.
library;

import 'dart:convert';
import 'dart:io';

import 'package:protocol/cosigner_v1.dart' as cs;
import 'package:test/test.dart';

import 'package:app_core/passkey/escrow_public_state.dart';
import 'package:app_core/passkey/key_derivation.dart';
import 'package:app_core/sessions/service_delivery.dart';

import 'support/ceremony.dart';

void main() {
  group('an escrow listed by the cosigner', () {
    test('becomes public state a new device can rebuild from', () async {
      final c = await ceremony(await walletPolynomial(seed(1)));
      final summary = cs.EscrowSummary(
        escrowKey: '02${'AB' * 32}',
        walletIdentifier: c.walletId.serialize(),
        publicKeyPackageJson: jsonEncode(c.pkp.toJson()),
        context: List<int>.filled(16, 7),
      );
      final escrow = EscrowPublicState.fromSummary(summary,
          walletIdentifier: c.walletId, minSigners: 2)!;
      expect(escrow.escrowKeyHex, '02${'ab' * 32}');
      expect(escrow.contextHex, '07' * 16);
      expect(escrow.wallet.identifier, c.walletId);
      // And it round-trips through what the device stores.
      expect(EscrowPublicState.fromJson(escrow.toJson()).contextHex, escrow.contextHex);
    });

    test('one minted before its context was recorded is left out: no passkey can rebuild it',
        () async {
      final c = await ceremony(await walletPolynomial(seed(2)));
      final summary = cs.EscrowSummary(
        escrowKey: '02${'ab' * 32}',
        walletIdentifier: c.walletId.serialize(),
        publicKeyPackageJson: jsonEncode(c.pkp.toJson()),
      );
      expect(EscrowPublicState.fromSummary(summary, walletIdentifier: c.walletId, minSigners: 2),
          isNull);
    });

    test("one listed under another wallet's identifier is refused", () async {
      final mine = await ceremony(await walletPolynomial(seed(3)));
      final theirs = await ceremony(await walletPolynomial(seed(4)));
      final summary = cs.EscrowSummary(
        escrowKey: '02${'ab' * 32}',
        walletIdentifier: theirs.walletId.serialize(),
        publicKeyPackageJson: jsonEncode(theirs.pkp.toJson()),
        context: List<int>.filled(16, 7),
      );
      expect(
        () => EscrowPublicState.fromSummary(summary,
            walletIdentifier: mine.walletId, minSigners: 2),
        throwsStateError,
      );
    });
  });

  group('where a pairing contribution may go in the clear', () {
    test('an address on this machine or a private network', () {
      for (final host in ['localhost', '127.0.0.1', '::1', '10.0.0.5', '172.16.9.9', '192.168.1.2']) {
        expect(isLocalDevelopmentHost(host), isTrue, reason: host);
      }
    });

    test('never a name, whatever it starts with, and never a public address', () {
      for (final host in [
        '10.attacker.com',
        '192.168.evil.io',
        '172.16.example.net',
        'localhost.evil.com',
        'example.com',
        '8.8.8.8',
        '172.32.0.1',
        '2001:db8::1',
      ]) {
        expect(isLocalDevelopmentHost(host), isFalse, reason: host);
      }
    });
  });

  group('what counts as delivered', () {
    /// A service on this machine that answers every delivery with [status].
    Future<HttpServer> answering(int status, String body) async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((request) async {
        await request.drain<void>();
        request.response
          ..statusCode = status
          ..write(body);
        await request.response.close();
      });
      return server;
    }

    const contribution = ServiceContribution(
      escrowKeyHex: '02ab',
      attemptIdHex: 'aa',
      serviceIdentifierHex: '44',
      contributionHex: '55',
    );

    test('"ready" — the service holds both halves and they check out', () async {
      final server = await answering(200, '{"state":"ready"}');
      addTearDown(() => server.close(force: true));
      await HttpServiceDelivery().deliver('http://127.0.0.1:${server.port}', contribution);
    });

    test('"waiting" is not delivered: the half that should be there first is not', () async {
      // The cosigner's half always reaches the service before the wallet learns where to send its
      // own, so a service still waiting for it has lost it — and confirming would vouch for a
      // pairing that can never finish.
      final server = await answering(202, '{"state":"waiting"}');
      addTearDown(() => server.close(force: true));
      await expectLater(
        HttpServiceDelivery().deliver('http://127.0.0.1:${server.port}', contribution),
        throwsA(isA<ServiceDeliveryException>().having((e) => e.refused, 'refused', isTrue)),
      );
    });
  });
}
