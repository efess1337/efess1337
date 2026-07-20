"""
slprov2 Auth admin CLI (stdlib only)
  python admin_cli.py create --username demo --password demo123 --days 30
  python admin_cli.py list
  python admin_cli.py ban --username demo
  python admin_cli.py unban --username demo
  python admin_cli.py reset-hwid --username demo
  python admin_cli.py extend --username demo --days 30
"""
from __future__ import annotations

import argparse
import secrets
import sqlite3
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "slprov2_auth.db"


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_db() -> None:
    from server import init_db, hash_password  # noqa: F401

    init_db()


def cmd_create(args: argparse.Namespace) -> None:
    from server import hash_password

    ensure_db()
    license_key = "SLPRO-" + secrets.token_hex(8).upper()
    expires = None if args.days <= 0 else int(time.time()) + args.days * 86400
    ph = hash_password(args.password)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO users(username, password_hash, license_key, hwid, expires_at, banned, note, created_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                args.username.strip(),
                ph,
                license_key,
                None,
                expires,
                0,
                args.note or "",
                int(time.time()),
            ),
        )
    print(f"[+] user created: {args.username}")
    print(f"    license_key : {license_key}")
    print(
        f"    expires     : {'never' if expires is None else time.strftime('%Y-%m-%d %H:%M', time.localtime(expires))}"
    )


def cmd_list(_: argparse.Namespace) -> None:
    ensure_db()
    with db() as conn:
        rows = conn.execute(
            "SELECT username, license_key, hwid, expires_at, banned, last_login_at FROM users ORDER BY id"
        ).fetchall()
    if not rows:
        print("(no users)")
        return
    for r in rows:
        exp = "never" if r["expires_at"] is None else time.strftime("%Y-%m-%d", time.localtime(r["expires_at"]))
        print(
            f"- {r['username']:16} ban={r['banned']} exp={exp:10} hwid={(r['hwid'] or '-'):20} key={r['license_key']}"
        )


def cmd_ban(args: argparse.Namespace) -> None:
    with db() as conn:
        conn.execute("UPDATE users SET banned = 1 WHERE username = ? COLLATE NOCASE", (args.username,))
    print(f"[+] banned {args.username}")


def cmd_unban(args: argparse.Namespace) -> None:
    with db() as conn:
        conn.execute("UPDATE users SET banned = 0 WHERE username = ? COLLATE NOCASE", (args.username,))
    print(f"[+] unbanned {args.username}")


def cmd_reset_hwid(args: argparse.Namespace) -> None:
    with db() as conn:
        conn.execute("UPDATE users SET hwid = NULL WHERE username = ? COLLATE NOCASE", (args.username,))
        conn.execute(
            "UPDATE sessions SET revoked = 1 WHERE user_id = (SELECT id FROM users WHERE username = ? COLLATE NOCASE)",
            (args.username,),
        )
    print(f"[+] hwid reset for {args.username}")


def cmd_extend(args: argparse.Namespace) -> None:
    with db() as conn:
        row = conn.execute(
            "SELECT expires_at FROM users WHERE username = ? COLLATE NOCASE",
            (args.username,),
        ).fetchone()
        if not row:
            print("user not found")
            return
        base = int(time.time())
        if row["expires_at"] and int(row["expires_at"]) > base:
            base = int(row["expires_at"])
        new_exp = base + args.days * 86400
        conn.execute(
            "UPDATE users SET expires_at = ? WHERE username = ? COLLATE NOCASE",
            (new_exp, args.username),
        )
    print(f"[+] extended {args.username} -> {time.strftime('%Y-%m-%d %H:%M', time.localtime(new_exp))}")


def main() -> None:
    p = argparse.ArgumentParser(prog="slprov2-admin")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create")
    c.add_argument("--username", required=True)
    c.add_argument("--password", required=True)
    c.add_argument("--days", type=int, default=30, help="0 = never expires")
    c.add_argument("--note", default="")
    c.set_defaults(func=cmd_create)

    l = sub.add_parser("list")
    l.set_defaults(func=cmd_list)

    b = sub.add_parser("ban")
    b.add_argument("--username", required=True)
    b.set_defaults(func=cmd_ban)

    u = sub.add_parser("unban")
    u.add_argument("--username", required=True)
    u.set_defaults(func=cmd_unban)

    r = sub.add_parser("reset-hwid")
    r.add_argument("--username", required=True)
    r.set_defaults(func=cmd_reset_hwid)

    e = sub.add_parser("extend")
    e.add_argument("--username", required=True)
    e.add_argument("--days", type=int, required=True)
    e.set_defaults(func=cmd_extend)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
