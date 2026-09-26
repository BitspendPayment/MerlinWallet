import 'package:app_core/cosigner/connection.dart';
import 'package:grpc/grpc.dart';
import 'package:test/test.dart';

/// Every ceremony a connection opens has to be one `cancelOpenStreams` can reach: a stream built
/// outside the connection's tracking is one a cancelled operation cannot unwind, and the share in
/// its driver's frame outlives the operation. The escrow streams were exactly that.
void main() {
  test('every ceremony stream is tracked, and cancelling ends them all', () async {
    // Nothing listens: what is under test is bookkeeping, settled before anything is dialled.
    final conn = CosignerConnection(ClientChannel('127.0.0.1',
        port: 9, options: const ChannelOptions(credentials: ChannelCredentials.insecure())));
    final opened = [
      conn.openSign(),
      conn.openDkg(),
      conn.openSend(),
      conn.openSettle(),
      conn.openEscrow(),
      conn.openPairService(),
      conn.openEscrowReclaim(),
    ];
    expect(conn.streamsInFlight, opened.length);
    await conn.cancelOpenStreams();
    expect(conn.streamsInFlight, 0);
    await conn.shutdown();
  });
}
