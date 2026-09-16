/// Where the CLI keeps wallets: `~/.merlin-cli/`, or `MERLIN_CLI_HOME`.
///
/// **Regtest only, and plaintext.** A wallet here is two files: a software passkey (a P-256 private
/// key in JSON, as `passkey-client` writes it) and a Hive box with the wallet's FROST share. Either
/// alone is enough to act as that wallet against its enclave.
///
/// Wallets are kept **per enclave boot**, under the fingerprint of that boot's trust root. A dev
/// enclave rebuilds its store from nothing each time it starts, so a passkey from an earlier boot
/// names a tenant that no longer exists — and a share from one would be paired with a cosigner that
/// never heard of it. Scoping by root makes a new boot a clean slate instead of a confusing one.
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;

class WalletRecord {
  WalletRecord(this.name, {this.groupKey});
  final String name;
  String? groupKey;

  Map<String, dynamic> toJson() => {'group_key': groupKey};
}

class CliHome {
  CliHome._(this.dir, this.enclaveId);

  /// The home for the enclave whose trust root is [trustRoot].
  static CliHome forEnclave(List<int> trustRoot) {
    final root = Platform.environment['MERLIN_CLI_HOME'] ??
        '${Platform.environment['HOME']}/.merlin-cli';
    final id = crypto.sha256.convert(trustRoot).toString().substring(0, 16);
    final dir = Directory('$root/enclaves/$id')..createSync(recursive: true);
    Directory('${dir.path}/passkeys').createSync();
    return CliHome._(dir, id);
  }

  final Directory dir;
  final String enclaveId;

  File get _index => File('${dir.path}/wallets.json');
  String get hivePath => '${dir.path}/hive';

  File passkey(String name) => File('${dir.path}/passkeys/$name.json');

  /// The Hive box a wallet's share lives in.
  String storageId(String name) => 'cli_$name';

  Map<String, WalletRecord> wallets = {};
  String? active;

  void load() {
    if (!_index.existsSync()) return;
    final json = jsonDecode(_index.readAsStringSync()) as Map<String, dynamic>;
    active = json['active'] as String?;
    wallets = {
      for (final e in (json['wallets'] as Map<String, dynamic>).entries)
        e.key: WalletRecord(e.key, groupKey: (e.value as Map<String, dynamic>)['group_key'] as String?),
    };
  }

  void save() => _index.writeAsStringSync(const JsonEncoder.withIndent('  ').convert({
        'active': active,
        'wallets': {for (final w in wallets.values) w.name: w.toJson()},
      }));
}
