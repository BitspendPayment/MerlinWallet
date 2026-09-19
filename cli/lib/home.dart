/// Where the CLI keeps wallets: `~/.merlin-cli/`, or `MERLIN_CLI_HOME`.
///
/// **Regtest only, and plaintext.** A wallet here is two files: a software passkey (a P-256 private
/// key in JSON, as `passkey-client` writes it) and a Hive box with the wallet's public state — who
/// it is, its delegate, its exits. The box holds no key: the share is rebuilt for each operation
/// from the passkey and the cosigner. **The passkey file is the wallet**, in the clear: it approves
/// every call and its PRF derives the key, so it alone is enough to act as that wallet.
///
/// Wallets are kept **per enclave store**. A kept store (`make up-enclave`) has an id that survives
/// restarts, so its wallets do too. An enclave booted without one starts from nothing, so its
/// wallets are kept under that boot's trust root instead: a passkey from an earlier boot would name
/// a tenant that no longer exists, and a wallet would be paired with a cosigner that never heard of
/// it. Either way a new store is a clean slate rather than a confusing one.
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

  /// The home for an enclave: its kept store's [storeId], or else this boot's [trustRoot].
  static CliHome forEnclave(List<int> trustRoot, {String? storeId}) {
    final root = Platform.environment['MERLIN_CLI_HOME'] ??
        '${Platform.environment['HOME']}/.merlin-cli';
    final id = storeId != null && storeId.isNotEmpty
        ? 'store-${storeId.substring(0, 16)}'
        : crypto.sha256.convert(trustRoot).toString().substring(0, 16);
    final dir = Directory('$root/enclaves/$id')..createSync(recursive: true);
    Directory('${dir.path}/passkeys').createSync();
    return CliHome._(dir, id);
  }

  final Directory dir;
  final String enclaveId;

  File get _index => File('${dir.path}/wallets.json');
  String get hivePath => '${dir.path}/hive';

  File passkey(String name) => File('${dir.path}/passkeys/$name.json');

  /// The Hive box a wallet's public state lives in.
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
