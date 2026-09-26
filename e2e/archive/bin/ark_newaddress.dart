/// Generate a new Ark address (creates a throwaway user via DKG).
/// Requires: MPC server running.
/// Usage: dart run bin/ark_newaddress.dart [server_host:port]
import 'dart:io';
import 'package:grpc/grpc.dart';
import 'package:hive/hive.dart';
import 'package:app_core/client.dart';

Future<void> main(List<String> args) async {
  final hostPort = args.isNotEmpty ? args[0] : '127.0.0.1:50051';
  final parts = hostPort.split(':');
  final host = parts[0];
  final port = parts.length > 1 ? int.parse(parts[1]) : 50051;

  // Initialize Hive in a temp directory
  final tmpDir = await Directory.systemTemp.createTemp('ark_newaddr_');
  Hive.init(tmpDir.path);

  final channel = ClientChannel(host, port: port,
      options: const ChannelOptions(credentials: ChannelCredentials.insecure()));

  final client = MpcClient(channel);
  await client.doDkg();

  final arkAddress = await client.getArkAddress();
  print(arkAddress);

  await channel.shutdown();
  await tmpDir.delete(recursive: true);
}
