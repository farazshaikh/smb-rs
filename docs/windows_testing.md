# Windows VM Testing Strategy

## Goal

Validate rustsmb against a real Windows SMB client to catch protocol
deviations that smbclient (Linux) and impacket (Python) don't exercise.

## Prerequisites

- Windows 10/11 or Server 2019+ VM with VirtualBox/KVM/Hyper-V
- Host-only or NAT network so the VM can reach the rustsmb host
- rustsmb running on the host, reachable from the VM guest IP

## Test matrix

| # | Scenario | Expected | Command (from Windows) |
|---|----------|----------|------------------------|
| 1 | Map drive (plaintext) | Drive letter appears in Explorer | `net use Z: \\\\HOST\\public /user:alice secret123` |
| 2 | Map drive (encrypted) | Same, sealed session | `net use Z: \\\\HOST\\public /user:alice secret123 /req:encrypt` |
| 3 | Map drive (signing required) | Same, signed packets | `net use Z: \\\\HOST\\public /user:alice secret123 /req:sign` |
| 4 | Dir listing | Files visible | `dir Z:\\` |
| 5 | Read/write/copy/delete | All succeed | Standard file operations via cmd/explorer |
| 6 | Large file (>64 KiB) | Multi-credit R/W works | `copy large.bin Z:\\` |
| 7 | Disconnect/reconnect | Clean reconnect | `net use Z: /delete` then re-map |
| 8 | Bad credentials | Access denied | `net use Z: \\\\HOST\\public /user:alice wrongpass` |

## Automation approach

### Option A: PowerShell remoting into VM

1. Enable WinRM on the Windows VM
2. From CI, use `pywinrm` or `ansible.windows.win_*` modules to execute
   PowerShell commands inside the VM
3. Script drives `net use`, file ops, and asserts results

### Option B: Vagrant + provisioned test runner

```ruby
# Vagrantfile
Vagrant.configure("2") do |config|
  config.vm.box = "gusztavvargadr/windows-11"
  config.vm.provision "shell", path: "provision_smb_client.ps1"
end
```

Provision script installs test harness that:
1. Waits for rustsmb to be reachable on host
2. Runs `New-SmbMapping -RemotePath \\HOST\public`
3. Executes file I/O assertions
4. Reports pass/fail per scenario back to CI

### Option C: Docker + samba-test-container

Use a container with Samba client tools configured identically to our
existing smbclient tests. Less valuable than a true Windows client but
easier to automate.

## Known risks for first Windows contact

- **Preauth integrity hash**: our SHA-512 chain must match exactly.
  Any offset error causes immediate disconnect.
- **Signing key derivation**: AES-CMAC key must match Windows'
  derivation from the exported session key.
- **Credit handling**: Windows may send CreditCharge > 1 before we've
  granted enough credits; lenient policy should handle this.
- **srvsvc response format**: template-based response may not match
  what Windows expects for arbitrary share sets.

## Success criteria

All 8 scenarios pass without errors. File contents match after
round-trip. No server-side panics or unexpected disconnects in logs.
