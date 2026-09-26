import 'package:app_core/cosigner/connection.dart';
import 'package:grpc/grpc.dart';
import 'package:test/test.dart';

// Nothing listens on the port: what is under test is how many times the approver is asked, which is
// settled before anything is dialled.
CosignerConnection _connection(List<String> asked) => CosignerConnection(
      ClientChannel('127.0.0.1',
          port: 9, options: const ChannelOptions(credentials: ChannelCredentials.insecure())),
      approver: (path) async {
        asked.add(path);
        return {'authorization': 'Bearer ${asked.length}'};
      },
    );

Future<void> _openSend(CosignerConnection conn) async {
  final duplex = conn.openSend();
  try {
    await duplex.next('anything');
  } catch (_) {
    // Refused at connect, after the approval was taken.
  }
}

void main() {
  test('a call approved ahead is not approved again', () async {
    final asked = <String>[];
    final conn = _connection(asked);

    await conn.approveAhead('Send');
    expect(asked, ['/cosigner.v1.Cosigner/Send']);

    await _openSend(conn);
    expect(asked, hasLength(1));

    // Used once: the next call asks again.
    await _openSend(conn);
    expect(asked, hasLength(2));
  });

  test('an approval ahead is kept for its own method only', () async {
    final asked = <String>[];
    final conn = _connection(asked);

    await conn.approveAhead('Settle');
    await _openSend(conn);
    expect(asked, ['/cosigner.v1.Cosigner/Settle', '/cosigner.v1.Cosigner/Send']);
  });

  test('a discarded approval is not used', () async {
    final asked = <String>[];
    final conn = _connection(asked);

    await conn.approveAhead('Send');
    conn.discardApproval('Send');
    await _openSend(conn);
    expect(asked, hasLength(2));
  });
}
