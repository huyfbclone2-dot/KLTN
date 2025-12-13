#!/usr/bin/env python3
import os
import re
import json
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# -------- Helpers --------
LINE_RE = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s*(?:#\s*(.*))?$")

def read_banned_file(path: Path) -> List[Dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            # fallback: first token as IP
            ip = line.split()[0]
            meta = line[len(ip):].strip()
            out.append({"ip": ip, "meta": meta})
            continue
        ip = m.group(1)
        meta = (m.group(2) or "").strip()
        out.append({"ip": ip, "meta": meta})
    return out

def remove_ip_from_file(path: Path, ip: str) -> None:
    if not path.exists():
        return
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    kept = []
    for ln in lines:
        if ln.strip().startswith(ip + " " ) or ln.strip() == ip or ln.strip().startswith(ip + "\t"):
            continue
        # also remove pattern "ip  # ..."
        if re.match(rf"^\s*{re.escape(ip)}\s*(#.*)?$", ln.strip()):
            continue
        kept.append(ln)
    path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")

def iptables_delete_all(ip: str, chain: str) -> int:
    """
    Delete ALL matching DROP rules for this IP in a chain.
    Return: number of deletions.
    """
    deleted = 0
    while True:
        # check existence
        check = subprocess.run(["iptables", "-C", chain, "-s", ip, "-j", "DROP"], capture_output=True)
        if check.returncode != 0:
            break
        # delete one occurrence
        subprocess.run(["iptables", "-D", chain, "-s", ip, "-j", "DROP"], check=True)
        deleted += 1
    return deleted

# -------- API --------
class UnbanReq(BaseModel):
    ip: str

def make_app(outdir: Path, ban_file: str, chain: str, token: str, allow_origin: str):
    app = FastAPI(title="IDS Ban API")

    # CORS: allow dashboard origin (http://localhost:8000 by default)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[allow_origin] if allow_origin else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    banned_path = outdir / ban_file

    def auth(x_auth_token: Optional[str]):
        if token and x_auth_token != token:
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/api/bans")
    def get_bans(x_auth_token: Optional[str] = Header(default=None)):
        auth(x_auth_token)
        return {"items": read_banned_file(banned_path)}

    @app.post("/api/unban")
    def unban(req: UnbanReq, x_auth_token: Optional[str] = Header(default=None)):
        auth(x_auth_token)
        ip = req.ip.strip()
        if not ip:
            raise HTTPException(status_code=400, detail="Missing IP")

        try:
            deleted = iptables_delete_all(ip, chain=chain)
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"iptables error: {e}")

        # Update file only if we actually removed rules (or if you want always remove from file)
        if deleted > 0:
            remove_ip_from_file(banned_path, ip)

        return {"ip": ip, "deleted_rules": deleted, "chain": chain}

    return app


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True, help="Folder that contains banned_ips.txt")
    ap.add_argument("--ban_file", default="banned_ips.txt")
    ap.add_argument("--chain", default="INPUT", help="iptables chain (INPUT or IDS_BLOCK if you used a custom chain)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8001)
    ap.add_argument("--token", default=os.getenv("BAN_API_TOKEN", ""), help="Optional auth token")
    ap.add_argument("--allow_origin", default="http://localhost:8000", help="Dashboard origin for CORS")
    args = ap.parse_args()

    outdir = Path(args.outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    app = make_app(outdir, args.ban_file, args.chain, args.token, args.allow_origin)

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)

if __name__ == "__main__":
    main()
