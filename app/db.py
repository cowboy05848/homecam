import os
from sqlalchemy import create_engine, text

DB_URL = os.getenv("DB_URL")
if not DB_URL:
    DB_URL = "mysql+pymysql://homecam:homecam1234%40@localhost/homecam?charset=utf8mb4"

engine = create_engine(DB_URL, future=True, pool_pre_ping=True)

DDL = """
CREATE TABLE IF NOT EXISTS vpn_tunnels (
  device_id      VARCHAR(32) PRIMARY KEY,
  owner_user_id  INT         NULL,
  client_pubkey  TEXT        NOT NULL,
  wg_pubkey      TEXT        NULL,
  assigned_ip    VARCHAR(43) NOT NULL,
  allowed_ip     VARCHAR(43) NOT NULL,
  status         VARCHAR(16) NOT NULL DEFAULT 'active',
  updated_at     TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  created_at     TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

def init_db():
    with engine.begin() as conn:
        conn.exec_driver_sql(DDL)

def upsert_vpn(device_id, owner_user_id, client_pubkey, assigned_ip, allowed_ip, status="active"):
    with engine.begin() as conn:
        conn.execute(text("""
        INSERT INTO vpn_tunnels(device_id, owner_user_id, client_pubkey, assigned_ip, allowed_ip, status)
        VALUES (:device_id, :owner_user_id, :client_pubkey, :assigned_ip, :allowed_ip, :status)
        ON DUPLICATE KEY UPDATE
          owner_user_id = VALUES(owner_user_id),
          client_pubkey = VALUES(client_pubkey),
          assigned_ip   = VALUES(assigned_ip),
          allowed_ip    = VALUES(allowed_ip),
          status        = VALUES(status),
          updated_at    = CURRENT_TIMESTAMP
        """), dict(
            device_id=device_id,
            owner_user_id=owner_user_id,
            client_pubkey=client_pubkey,
            assigned_ip=assigned_ip,
            allowed_ip=allowed_ip,
            status=status
        ))

def fetch_assigned_ips() -> set[str]:
    with engine.begin() as conn:
        rows = conn.execute(text(
            "SELECT assigned_ip FROM vpn_tunnels WHERE status <> 'removed'"
        )).fetchall()
    return {r[0] for r in rows}

def mark_vpn_removed(device_id: str):
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE vpn_tunnels SET status='removed' WHERE device_id=:d"
        ), {"d": device_id})

def fetch_owner_user_id(device_id: str):
    with engine.begin() as conn:
        row = conn.execute(text(
            "SELECT owner_user_id FROM vpn_tunnels WHERE device_id=:d"
        ), {"d": device_id}).fetchone()
    return None if not row else row[0]

def fetch_vpn_by_device(device_id: str):
    with engine.begin() as conn:
        row = conn.execute(text(
            "SELECT device_id, owner_user_id, client_pubkey, assigned_ip, allowed_ip, status "
            "FROM vpn_tunnels WHERE device_id=:d"
        ), {"d": device_id}).fetchone()
    if not row:
        return None
    keys = ["device_id", "owner_user_id", "client_pubkey", "assigned_ip", "allowed_ip", "status"]
    return dict(zip(keys, row))
