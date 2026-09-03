#!/usr/bin/env python3
"""One-time (idempotent) local setup for the protocol suite (test/wpts).

The submodule is an unmodified checkout of Microsoft's official MS-SMB2
Server Test Suite, built to run against a Windows SUT reachable on port 445.
Since rustsmb runs unprivileged (no port 445) and the SUT here is a Linux
box, this script:

1. Patches ProtoSDK's Smb2Client so the TCP connect path honours a
   SMB2_SUT_PORT env var override -- the test suite otherwise hardcodes 445
   for every TCP connection; there is no ptfconfig property for it.
2. Points the ptfconfig at a local, non-Windows SUT (loopback addresses,
   Platform=NonWindows, no AD domain).

Both edits land in the submodule's own working tree (test/wpts is a separate
git checkout pinned by gitlink in the parent repo), so they show up as
uncommitted changes under `test/wpts` -- that's expected, not something to
commit. Safe to re-run: both edits are idempotent (checked before applying).
"""
import re
import sys
from pathlib import Path

WPTS = Path(__file__).resolve().parents[1] / "wpts"
SMB2_CLIENT = WPTS / "ProtoSDK/MS-SMB2/Client/Smb2Client.cs"
COMMON_PTFCONFIG = WPTS / "TestSuites/FileServer/src/Common/TestSuite/CommonTestSuite.deployment.ptfconfig"
SMB2_PTFCONFIG = WPTS / "TestSuites/FileServer/src/SMB2/TestSuite/MS-SMB2_ServerTestSuite.deployment.ptfconfig"

PORT_OVERRIDE_MARKER = "SMB2_SUT_PORT"
PORT_OVERRIDE_SNIPPET = """\
            var sutPortOverride = Environment.GetEnvironmentVariable("SMB2_SUT_PORT");
            if (!string.IsNullOrEmpty(sutPortOverride) && ushort.TryParse(sutPortOverride, out var overridePort))
            {
                serverPort = overridePort;
            }
"""
CONNECT_SIGNATURE = (
    "private void Connect(Smb2TransportType transportType, string serverName, "
    "string clientName, IPAddress serverIp, IPAddress clientIp, ushort serverPort)\n"
    "        {\n"
)

# Redirect the SUT identity from the upstream ptfconfig's Windows domain
# fixture to a local, standalone Linux server under test.
COMMON_PROPERTY_OVERRIDES = {
    "SutComputerName": "127.0.0.1",
    "SutIPAddress": "127.0.0.1",
    "DomainName": "",
    "ClientNic1IPAddress": "127.0.0.1",
    "ClientNic2IPAddress": "127.0.0.1",
    "Platform": "NonWindows",
}
SMB2_PROPERTY_OVERRIDES = {
    "SutAlternativeIPAddress": "127.0.0.1",
}


def patch_smb2_client() -> bool:
    text = SMB2_CLIENT.read_text()
    if PORT_OVERRIDE_MARKER in text:
        return False
    at = text.find(CONNECT_SIGNATURE)
    if at == -1:
        sys.exit(f"setup_protocol: could not find Connect() signature in {SMB2_CLIENT}")
    insert_at = at + len(CONNECT_SIGNATURE)
    SMB2_CLIENT.write_text(text[:insert_at] + PORT_OVERRIDE_SNIPPET + text[insert_at:])
    return True


def set_properties(path: Path, overrides: dict[str, str]) -> int:
    text = path.read_text()
    changed = 0
    for name, value in overrides.items():
        pattern = re.compile(rf'(<Property name="{re.escape(name)}" value=")[^"]*(")')
        text, n = pattern.subn(rf"\g<1>{value}\g<2>", text)
        changed += n
    path.write_text(text)
    return changed


def main() -> None:
    patched = patch_smb2_client()
    print(f"Smb2Client.cs SMB2_SUT_PORT patch: {'applied' if patched else 'already present'}")

    n = set_properties(COMMON_PTFCONFIG, COMMON_PROPERTY_OVERRIDES)
    n += set_properties(SMB2_PTFCONFIG, SMB2_PROPERTY_OVERRIDES)
    print(f"ptfconfig: {n} propert{'y' if n == 1 else 'ies'} set for a local non-Windows SUT")


if __name__ == "__main__":
    main()
