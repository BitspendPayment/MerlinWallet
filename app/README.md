# Merlin Wallet Flutter app

The Android app holds Bitcoin as Ark VTXOs. It uses `../app-core` for wallet
operations and `../protocol` for shared messages.

Onboarding selects a cosigner, creates a passkey, runs distributed key generation,
and asks for an exit address in another wallet. Returning users select
“I already have a wallet” and restore using their original passkey and cosigner.
Wallets created before recovery support cannot be restored this way.

The app supports Ark sends, boarding confirmed Bitcoin deposits, approving or
declining payment requests, managing contacts, and exporting pre-signed exits.
Sending payment requests is not supported yet. Contacts and requests are cached
locally; pull down on their screens to fetch them after restoring.

The wallet reconstructs its signing share for each operation rather than storing
it. A signed delegate enables one automatic renewal without the phone; the new
outputs need another owner-approved seal for renewal and signed exits. The app
does not provide direct on-chain spending or broadcast a complete exit path.

## Development

See the [repository setup and build instructions](../README.md#build--run) for
native libraries and backend services, and the [Mutinynet runbook](../infrastructure/mutinynet-qemu/README.md)
for that deployment. Run Flutter commands from this directory:

```sh
flutter pub get
flutter run
flutter analyze
flutter test
```

Local server presets are available in debug builds. The emulator uses `10.0.2.2`;
a physical phone uses `127.0.0.1` with the required `adb reverse` port forwards.
