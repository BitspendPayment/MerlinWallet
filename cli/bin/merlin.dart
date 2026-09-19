/// merlin — a regtest wallet REPL against the cosigner inside a dev enclave.
///
///   dart run bin/merlin.dart                 the REPL
///   dart run bin/merlin.dart <command> ...   one command, then exit
///
/// **Regtest only.** Passkeys are kept in plaintext under ~/.merlin-cli — and a passkey is the
/// whole wallet: no share is stored, because the key is rebuilt from the passkey for each operation.
library;

import 'dart:convert';
import 'dart:io';

import 'package:app_core/enclave/attestation.dart';
import 'package:app_core/enclave/gate.dart';
import 'package:merlin_cli/cli.dart';

Future<void> main(List<String> args) async {
  final Cli cli;
  try {
    cli = fromEnvironment();
    await cli.start();
  } catch (e) {
    stderr.writeln(e);
    exitCode = 1;
    return;
  }

  try {
    if (args.isNotEmpty) {
      if (!await _attempt(cli, args.join(' '))) exitCode = 1;
      return;
    }
    print('merlin — enclave ${cli.home.enclaveId}, wallets in ${cli.home.dir.path}');
    print('regtest only: passkeys are plaintext, and a passkey is the wallet. `help` for commands.');
    final lines = stdin.transform(utf8.decoder).transform(const LineSplitter());
    stdout.write('${cli.home.active ?? ''}> ');
    await for (final line in lines) {
      if (line.trim() == 'quit' || line.trim() == 'exit') break;
      await _attempt(cli, line);
      stdout.write('${cli.home.active ?? ''}> ');
    }
  } finally {
    await cli.close();
  }
}

/// One command, with its failure printed rather than thrown — a REPL that dies on a typo is no REPL.
Future<bool> _attempt(Cli cli, String line) async {
  try {
    await cli.run(line);
    return true;
  } on AttestationException catch (e) {
    stderr.writeln('refusing to talk to that enclave: ${e.message}');
  } on GateException catch (e) {
    stderr.writeln(e);
  } catch (e) {
    stderr.writeln('error: $e');
  }
  return false;
}
