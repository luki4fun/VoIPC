# Security policy

## Reporting a vulnerability

Report it privately on GitHub: **Security → Report a vulnerability** at
<https://github.com/luki4fun/voipc/security/advisories/new>. Please do not open a public
issue.

Tell us:
- the version;
- the part: relay, desktop app (Linux or Windows), Android, browser client, game SDK, or the
  release files;
- how to reproduce it.

**What happens next:**
- You get an answer within 7 days.
- The fix ships in a release, normally within 90 days of the report, and the advisory is
  published with it.
- You are credited, unless you ask not to be.

## Supported versions

Only the newest release gets security fixes. To get a fix, update the relay and the apps to
it.

A relay admits only apps of its own protocol version, and a release that changes it says so in
its notes' first line. Since 1.6 an app also talks to relays up to three protocols older, so
the apps can take a fix before their relay does ([docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)
§1).

A relay can update itself (`[update]`, [docs/OPERATING.md](docs/OPERATING.md) §14). It installs
only a release signed with the key the desktop updater trusts, for the version and the file
the feed names, and it is off unless the operator turns it on.

## What is not a vulnerability

These are documented limits ([README → Security](README.md#security),
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)):
- **Trust on first use.** This applies to a self-signed server, whose certificate fingerprint
  is shown at first contact, and to the first meeting of two accounts.
- **Guests.** A guest's identity is new on every connection and is not verified.
- **The browser client.** It runs the page the server serves, so a hostile server can serve a
  hostile client.
- **Unsigned Windows builds.** They are not Authenticode-signed; verify them as below instead.

## Verifying a download

Every release carries `SHA256SUMS`, and a build attestation for every file. The attestation
proves the file was built by this repository's release workflow from the tagged commit.

    sha256sum -c SHA256SUMS --ignore-missing
    gh attestation verify VoIPC_1.9.0-rc.1_amd64.AppImage --repo luki4fun/voipc

The relay's container image is attested the same way:

    gh attestation verify oci://ghcr.io/luki4fun/voipc-server:1.9.0-rc.1 --repo luki4fun/voipc

The Android APK is signed with the same certificate as every earlier VoIPC APK. Its SHA-256 is
`30d71722fe2bdd4bafc34fdaf5be34071f5dfaa399823237c7ae4ab7778a0fe9`. To check it:

    apksigner verify --print-certs VoIPC-android-1.9.0-rc.1.apk

The desktop app's own updater only installs an update signed for exactly the version it
announces.
