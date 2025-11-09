#!/usr/bin/env python3
import os, json, re, base64, socket, ipaddress, subprocess, logging

SOCK_PATH = "/run/wgdaemon/wg.sock"
LOG_DIR = "/var/log/wgdaemon"
LOG_FILE = os.path.join(LOG_DIR, "wgdaemon.log")

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

DEVICE_RE = re.compile(r"^[A-Za-z0-9._:-]{3,64}$")
B64_RE    = re.compile(r"^[A-Za-z0-9+/=]{43,44}$")
WG_NET    = ipaddress.ip_network("10.8.0.0/24")

def is_valid_pubkey_b64(s: str) -> bool:
    if not B64_RE.match(s or ""): return False
    try:
        raw = base64.b64decode(s)
        return len(raw) == 32
    except Exception:
        return False

def is_valid_cidr_32(c: str) -> bool:
    try:
        ipnet = ipaddress.ip_network(c, strict=False)
        return ipnet.prefixlen == 32 and ipnet.subnet_of(WG_NET)
    except Exception:
        return False

def handle(msg: dict) -> dict:
    action = msg.get("action")
    if action not in ("add_peer","remove_peer"):
        return {"ok": False, "error": "invalid_action"}

    device_id = msg.get("device_id")
    if not device_id or not DEVICE_RE.match(device_id):
        return {"ok": False, "error":"invalid_device_id"}

    if action == "add_peer":
        pub = msg.get("client_pubkey_b64")
        ip_cidr = msg.get("ip_cidr")
        if not (is_valid_pubkey_b64(pub) and is_valid_cidr_32(ip_cidr)):
            return {"ok": False, "error": "invalid_pubkey_or_ip"}
        try:
            subprocess.run(
                ["/usr/local/bin/wgctl.sh", "add-peer", device_id, pub, ip_cidr],
                check=True
            )
            return {"ok": True}
        except subprocess.CalledProcessError as e:
            logging.exception("add-peer failed")
            return {"ok": False, "error": f"wgctl_failed:{e.returncode}"}
    else:
        try:
            subprocess.run(
                ["/usr/local/bin/wgctl.sh", "remove-peer", device_id],
                check=True
            )
            return {"ok": True}
        except subprocess.CalledProcessError as e:
            logging.exception("remove-peer failed")
            return {"ok": False, "error": f"wgctl_failed:{e.returncode}"}

def main():
    try:
        os.unlink(SOCK_PATH)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK_PATH)
    os.chmod(SOCK_PATH, 0o660)
    try:
        import grp
        gid = grp.getgrnam("wgmgr").gr_gid
        os.chown(SOCK_PATH, -1, gid)
    except Exception:
        pass

    srv.listen(20)
    logging.info("wgdaemon up")

    while True:
        conn, _ = srv.accept()
        try:
            data = conn.recv(8192)
            if not data:
                conn.close(); continue
            try:
                req = json.loads(data.decode("utf-8"))
            except Exception:
                conn.sendall(b'{"ok":false,"error":"bad_json"}'); conn.close(); continue

            if len(json.dumps(req)) > 2048:
                conn.sendall(b'{"ok":false,"error":"payload_too_large"}'); conn.close(); continue

            resp = handle(req)
            conn.sendall(json.dumps(resp).encode("utf-8"))
        except Exception:
            logging.exception("server error")
            try: conn.sendall(b'{"ok":false,"error":"server_error"}')
            except Exception: pass
        finally:
            conn.close()

if __name__ == "__main__":
    main()
