#!/usr/bin/env python3
"""JSON-driven SMB actuator for the smb-rs conformance suite.

Reads one JSON request from stdin and writes one JSON response to stdout. The
Rust test harness owns the assertions; this driver only performs the SMB
operations against the server under test using the `smbprotocol` library.

Request:
  {
    "endpoint": {"host","port","user","pass","share",
                 "sign": bool?, "encrypt": bool?, "dialect": "3.1.1"?},
    "ops": [ {"op": "...", ...}, ... ]
  }

Response:
  {"ok": bool, "error": str?, "dialect": str, "signing": bool,
   "encryption": bool, "steps": [ {"op","ok","error"?, ...}, ... ]}

Handles opened by an op are addressed by a caller-chosen "handle" name so later
ops (write/read/close/ioctl) can reference them. All state lives for one driver
invocation; the connection is torn down on exit.
"""
import base64
import json
import sys
import uuid
import zlib

from smbprotocol.connection import Connection, Dialects
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import (
    Open, CreateDisposition, CreateOptions, FilePipePrinterAccessMask,
    ImpersonationLevel, ShareAccess, FileAttributes, FileInformationClass,
    DirectoryAccessMask, SMB2QueryInfoRequest, SMB2QueryInfoResponse,
    SMB2SetInfoRequest, SMB2LockElement, LockFlags,
)
from smbprotocol.file_info import (
    InfoType, FileStandardInformation, FileEndOfFileInformation,
    FileRenameInformation, FileDispositionInformation,
)

DISPOSITION = {
    "supersede": CreateDisposition.FILE_SUPERSEDE,
    "open": CreateDisposition.FILE_OPEN,
    "create": CreateDisposition.FILE_CREATE,
    "open_if": CreateDisposition.FILE_OPEN_IF,
    "overwrite": CreateDisposition.FILE_OVERWRITE,
    "overwrite_if": CreateDisposition.FILE_OVERWRITE_IF,
}

DIALECT = {
    "2.0.2": Dialects.SMB_2_0_2,
    "2.1": Dialects.SMB_2_1_0,
    "2.1.0": Dialects.SMB_2_1_0,
    "3.0": Dialects.SMB_3_0_0,
    "3.0.0": Dialects.SMB_3_0_0,
    "3.0.2": Dialects.SMB_3_0_2,
    "3.1.1": Dialects.SMB_3_1_1,
}


def _b64(data):
    return base64.b64encode(bytes(data)).decode("ascii")


def _unb64(text):
    return base64.b64decode(text.encode("ascii"))


def _parse_streams(buf):
    """Decode a FILE_STREAM_INFORMATION chain ([MS-FSCC] 2.4.40) into names."""
    streams = []
    off = 0
    while off + 24 <= len(buf):
        next_off = int.from_bytes(buf[off:off + 4], "little")
        name_len = int.from_bytes(buf[off + 4:off + 8], "little")
        size = int.from_bytes(buf[off + 8:off + 16], "little")
        name = buf[off + 24:off + 24 + name_len].decode("utf-16-le", errors="replace")
        streams.append({"name": name, "size": size})
        if next_off == 0:
            break
        off += next_off
    return streams


class Driver:
    def __init__(self, ep):
        self.ep = ep
        self.handles = {}
        want = ep.get("dialect")
        dialect = DIALECT[want] if want in DIALECT else None
        self.conn = Connection(uuid.uuid4().bytes, ep["host"], int(ep["port"]),
                               require_signing=bool(ep.get("sign", False)))
        self.conn.connect(dialect=dialect)
        self.session = Session(self.conn, ep.get("user", ""), ep.get("pass", ""),
                               require_encryption=bool(ep.get("encrypt", False)))
        self.session.connect()
        self.tree = TreeConnect(
            self.session, r"\\{}\{}".format(ep["host"], ep["share"]))
        self.tree.connect()

    def negotiated_dialect(self):
        return {v: k for k, v in DIALECT.items()}.get(self.conn.dialect,
                                                      hex(self.conn.dialect))

    def _open(self, step):
        name = step["handle"]
        directory = step.get("directory", False)
        access = step.get("access")
        if access is None:
            mask = (DirectoryAccessMask.FILE_LIST_DIRECTORY
                    | DirectoryAccessMask.FILE_READ_ATTRIBUTES
                    if directory else
                    FilePipePrinterAccessMask.GENERIC_READ
                    | FilePipePrinterAccessMask.GENERIC_WRITE)
        else:
            mask = int(access)
        options = (CreateOptions.FILE_DIRECTORY_FILE if directory
                   else CreateOptions.FILE_NON_DIRECTORY_FILE)
        if step.get("delete_on_close"):
            options |= CreateOptions.FILE_DELETE_ON_CLOSE
            # Delete-on-close requires DELETE access ([MS-SMB2] 3.3.5.9).
            mask |= FilePipePrinterAccessMask.DELETE
        attrs = (FileAttributes.FILE_ATTRIBUTE_DIRECTORY if directory
                 else FileAttributes.FILE_ATTRIBUTE_NORMAL)
        f = Open(self.tree, step["path"])
        f.create(
            ImpersonationLevel.Impersonation, mask, attrs,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE
            | ShareAccess.FILE_SHARE_DELETE,
            DISPOSITION[step.get("disposition", "open_if")], options)
        self.handles[name] = f
        return {"file_id": _b64(f.file_id)}

    def _write(self, step):
        f = self.handles[step["handle"]]
        if "fill_size" in step:
            seed = int(step.get("fill_seed", 7))
            data = bytes((i * seed) % 251 for i in range(int(step["fill_size"])))
        elif "data_b64" in step:
            data = _unb64(step["data_b64"])
        else:
            data = step["data"].encode("utf-8")
        n = f.write(data, step.get("offset", 0))
        return {"written": n, "crc32": zlib.crc32(data) & 0xFFFFFFFF}

    def _read(self, step):
        f = self.handles[step["handle"]]
        data = f.read(step.get("offset", 0), step["length"])
        out = {"length": len(data), "crc32": zlib.crc32(bytes(data)) & 0xFFFFFFFF}
        if len(data) <= 4096:
            out["data_b64"] = _b64(data)
        return out

    def _query_info(self, step):
        f = self.handles[step["handle"]]
        itype = {"file": InfoType.SMB2_0_INFO_FILE,
                 "filesystem": InfoType.SMB2_0_INFO_FILESYSTEM,
                 "security": InfoType.SMB2_0_INFO_SECURITY}[step.get("info_type", "file")]
        info_class = int(step.get("info_class", 5))
        req = SMB2QueryInfoRequest()
        req["info_type"] = itype
        req["file_info_class"] = info_class
        req["output_buffer_length"] = 65535
        req["additional_information"] = int(step.get("additional", 0))
        req["file_id"] = f.file_id
        request = self.conn.send(req, sid=self.session.session_id,
                                 tid=self.tree.tree_connect_id)
        resp = self.conn.receive(request)
        qr = SMB2QueryInfoResponse()
        qr.unpack(resp["data"].get_value())
        buf = bytes(qr["buffer"].get_value())
        out = {"length": len(buf)}
        if info_class == 5:  # FileStandardInformation
            fsi = FileStandardInformation()
            fsi.unpack(buf)
            out["end_of_file"] = int(fsi["end_of_file"].get_value())
            out["delete_pending"] = bool(fsi["delete_pending"].get_value())
        elif info_class == 22:  # FileStreamInformation
            out["streams"] = _parse_streams(buf)
        return out

    def _set_info(self, step):
        f = self.handles[step["handle"]]
        kind = step["kind"]
        if kind == "eof":
            info = FileEndOfFileInformation()
            info["end_of_file"] = int(step["size"])
            info_class = FileInformationClass.FILE_END_OF_FILE_INFORMATION
        elif kind == "rename":
            info = FileRenameInformation()
            info["replace_if_exists"] = bool(step.get("replace", True))
            name = step["new_name"].encode("utf-16-le")
            info["file_name"] = name
            info["file_name_length"] = len(name)
            info_class = FileInformationClass.FILE_RENAME_INFORMATION
        elif kind == "delete":
            info = FileDispositionInformation()
            info["delete_pending"] = True
            info_class = FileInformationClass.FILE_DISPOSITION_INFORMATION
        else:
            raise ValueError("unknown set_info kind " + kind)
        req = SMB2SetInfoRequest()
        req["info_type"] = InfoType.SMB2_0_INFO_FILE
        req["file_info_class"] = info_class
        req["buffer"] = info
        req["file_id"] = f.file_id
        request = self.conn.send(req, sid=self.session.session_id,
                                 tid=self.tree.tree_connect_id)
        self.conn.receive(request)
        return {"kind": kind}

    def _lock(self, step):
        f = self.handles[step["handle"]]
        kind = step.get("kind", "exclusive")
        flags = {
            "exclusive": LockFlags.SMB2_LOCKFLAG_EXCLUSIVE_LOCK,
            "shared": LockFlags.SMB2_LOCKFLAG_SHARED_LOCK,
            "unlock": LockFlags.SMB2_LOCKFLAG_UNLOCK,
        }[kind]
        if kind != "unlock" and step.get("fail_immediately", True):
            flags |= LockFlags.SMB2_LOCKFLAG_FAIL_IMMEDIATELY
        el = SMB2LockElement()
        el["offset"] = int(step.get("offset", 0))
        el["length"] = int(step.get("length", 1))
        el["flags"] = flags
        f.lock([el])
        return {"kind": kind}

    def _close(self, step):
        f = self.handles.pop(step["handle"])
        f.close()
        return {}

    def _list(self, step):
        name = step.get("handle", "__list__")
        if name not in self.handles:
            d = Open(self.tree, step.get("path", ""))
            d.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.FILE_LIST_DIRECTORY
                | DirectoryAccessMask.FILE_READ_ATTRIBUTES,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE)
            self.handles[name] = d
        d = self.handles[name]
        entries = d.query_directory(
            step.get("pattern", "*"),
            FileInformationClass.FILE_NAMES_INFORMATION)
        names = [e["file_name"].get_value().decode("utf-16-le") for e in entries]
        if step.get("close", True):
            self.handles.pop(name).close()
        return {"names": names}

    def _ioctl(self, step):
        from smbprotocol.ioctl import CtlCode, IOCTLFlags
        f = self.handles.get(step.get("handle"))
        file_id = f.file_id if f else b"\xff" * 16
        out = self.conn.send(
            self._ioctl_req(step["ctl_code"], file_id,
                            _unb64(step["input_b64"]) if "input_b64" in step
                            else b""),
            sid=self.session.session_id, tid=self.tree.tree_connect_id)
        resp = self.conn.receive(out)
        from smbprotocol.ioctl import SMB2IOCTLResponse
        payload = SMB2IOCTLResponse()
        payload.unpack(resp["data"].get_value())
        return {"output_b64": _b64(payload["buffer"].get_value())}

    def _ioctl_req(self, ctl_code, file_id, data):
        from smbprotocol.ioctl import SMB2IOCTLRequest, IOCTLFlags
        req = SMB2IOCTLRequest()
        req["ctl_code"] = ctl_code
        req["file_id"] = file_id
        req["max_output_response"] = 65536
        req["flags"] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        req["buffer"] = data
        return req

    def run(self, ops):
        steps = []
        ok = True
        for step in ops:
            entry = {"op": step["op"]}
            expect_fail = step.get("expect_fail", False)
            try:
                handler = getattr(self, "_" + step["op"])
                result = handler(step)
                if expect_fail:
                    entry["ok"] = False
                    entry["error"] = "expected failure but op succeeded"
                    ok = False
                    steps.append(entry)
                    break
                entry.update(result)
                entry["ok"] = True
            except Exception as exc:  # noqa: BLE001 - report to Rust harness
                if expect_fail:
                    entry["ok"] = True
                    entry["expected_error"] = "{}: {}".format(type(exc).__name__, exc)
                else:
                    entry["ok"] = False
                    entry["error"] = "{}: {}".format(type(exc).__name__, exc)
                    ok = False
                    steps.append(entry)
                    break
            steps.append(entry)
        return ok, steps

    def close(self):
        for f in list(self.handles.values()):
            try:
                f.close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
        try:
            self.tree.disconnect()
            self.session.disconnect()
            self.conn.disconnect(True)
        except Exception:  # noqa: BLE001
            pass


def main():
    req = json.load(sys.stdin)
    ep = req["endpoint"]
    resp = {"ok": False, "steps": [], "dialect": "", "signing": False,
            "encryption": False}
    driver = None
    try:
        driver = Driver(ep)
        resp["dialect"] = driver.negotiated_dialect()
        resp["signing"] = bool(ep.get("sign", False))
        resp["encryption"] = bool(ep.get("encrypt", False))
        ok, steps = driver.run(req.get("ops", []))
        resp["ok"] = ok
        resp["steps"] = steps
        if not ok:
            failed = next((s for s in steps if not s["ok"]), None)
            resp["error"] = failed.get("error") if failed else "step failed"
    except Exception as exc:  # noqa: BLE001 - connection/negotiate failure
        resp["ok"] = False
        resp["error"] = "{}: {}".format(type(exc).__name__, exc)
    finally:
        if driver is not None:
            driver.close()
    json.dump(resp, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
