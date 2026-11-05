#!/usr/bin/env python3
"""Gera o portal de consulta criptografado (site estático).

Uso:
  build_portal.py --data certidoes.json --files arquivos.json --out site/ --password-file senha.txt [--alert 10]

certidoes.json : lista [{"id":..., "data":{...}}] (saída do db_query) ou lista de objetos com "id".
arquivos.json  : {"<id da certidão>": "/caminho/local/do/arquivo.pdf", ...}
Os dados e cada PDF são cifrados com AES-256-GCM; a chave vem da senha via PBKDF2-SHA256.
O salt é mantido entre execuções (lido do index.html existente) para que arquivos
inalterados não sejam regravados.
"""
import argparse, base64, hashlib, hmac, json, os, re, sys, datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 600_000
KEEP = ["empresa","documento","tipo","titulo","orgao","resultado","emissao","validade","numero","uf","municipio","abrangencia","substituida"]
HERE = os.path.dirname(os.path.abspath(__file__))

def b64(b): return base64.b64encode(b).decode()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True); ap.add_argument("--files", required=True)
    ap.add_argument("--out", required=True); ap.add_argument("--password-file", required=True)
    ap.add_argument("--alert", type=int, default=10)
    a = ap.parse_args()
    pw = open(a.password_file, encoding="utf-8").read().strip()
    os.makedirs(os.path.join(a.out, "f"), exist_ok=True)

    salt = None
    idx = os.path.join(a.out, "index.html")
    if os.path.exists(idx):
        m = re.search(r'"salt":\s*"([^"]+)"', open(idx, encoding="utf-8").read())
        if m: salt = base64.b64decode(m.group(1))
    salt = salt or os.urandom(16)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode())
    aes = AESGCM(key)

    raw = json.load(open(a.data, encoding="utf-8"))
    files = json.load(open(a.files, encoding="utf-8"))
    items, used = [], set()
    for r in raw:
        d = r.get("data", r); rid = r.get("id") or d.get("id")
        if d.get("substituida"): continue
        it = {k: d.get(k, "") for k in KEEP if k != "substituida"}; it["id"] = rid
        src = files.get(rid)
        if src and os.path.exists(src):
            content = open(src, "rb").read()
            tag = hmac.new(key, b"name:" + rid.encode() + hashlib.sha256(content).digest(), hashlib.sha256).hexdigest()[:24]
            iv = hmac.new(key, b"iv:" + tag.encode(), hashlib.sha256).digest()[:12]
            rel = f"f/{tag}.bin"; used.add(rel)
            dst = os.path.join(a.out, rel)
            if not os.path.exists(dst):
                open(dst, "wb").write(aes.encrypt(iv, content, None))
            ext = os.path.splitext(src)[1].lower()
            nome = re.sub(r'[\\/:*?"<>|]+', " ", f'{it["empresa"]} - {it["tipo"]} - {it["emissao"]}').strip() + (ext or ".pdf")
            it["arquivo"] = {"path": rel, "iv": b64(iv), "nome": nome,
                             "tipo": {".pdf":"application/pdf",".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg"}.get(ext,"application/octet-stream")}
        items.append(it)
    # remove arquivos cifrados que não são mais usados
    for fn in os.listdir(os.path.join(a.out, "f")):
        if f"f/{fn}" not in used: os.remove(os.path.join(a.out, "f", fn))

    payload_plain = json.dumps({"geradoEm": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "alertDias": a.alert, "items": items}, ensure_ascii=False).encode()
    iv = os.urandom(12)
    payload = {"salt": b64(salt), "iter": ITER, "iv": b64(iv), "ct": b64(aes.encrypt(iv, payload_plain, None))}
    tpl = open(os.path.join(HERE, "template.html"), encoding="utf-8").read()
    open(idx, "w", encoding="utf-8").write(tpl.replace("__PAYLOAD__", json.dumps(payload)))
    open(os.path.join(a.out, ".nojekyll"), "w").close()
    open(os.path.join(a.out, "robots.txt"), "w").write("User-agent: *\nDisallow: /\n")
    print(f"{len(items)} documentos, {len(used)} arquivos cifrados -> {a.out}")

if __name__ == "__main__":
    main()
