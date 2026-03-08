#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detector / Enricher ligero para matches de credenciales.
"""
import os
import re
import math
from collections import Counter

# ─── Import opcional de joblib ────────────────────────────────────────────────
try:
    import joblib
    HAS_JOBLIB = True
    #print('todo correcto')
except ImportError:
    HAS_JOBLIB = False
    print("[!] joblib no disponible. Instalar con: pip install joblib")

# ─── Variables globales del modelo ────────────────────────────────────────────
MODEL = None
SCALER = None
MODEL_PATH = os.environ.get("MODEL_PATH", "model.joblib")

# Small whitelist / known non-credential tokens (avoid FP)
WHITELIST = set([
    "changeme", "default", "example", "localhost", "admin", "user", "username",
    "test", "demo", "none", "null", "0", "1", "ytool"
])

RE_EMAIL = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
RE_URL = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')
RE_DIGIT_ONLY = re.compile(r'^\d+$')

HEX_LEN_MAP = {32: "MD5", 40: "SHA1", 64: "SHA256", 96: "SHA384", 128: "SHA512"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    l = len(s)
    return -sum((c / l) * math.log2(c / l) for c in counts.values())


def hex_ratio(s: str) -> float:
    if not s:
        return 0.0
    hex_chars = sum(1 for ch in s if ch in "0123456789abcdefABCDEF")
    return hex_chars / len(s)


def extract_features(token: str):
    """Características básicas para el modelo (debe coincidir con trainer.py)."""
    t = token or ""
    return [
        len(t),
        shannon_entropy(t),
        hex_ratio(t),
        int(bool(re.search(r"[A-Z]", t))),
        int(bool(re.search(r"[a-z]", t))),
        int(bool(re.search(r"\d", t))),
        int(bool(re.search(r"[^\w\s]", t))),
        int(t.startswith("$2") or t.startswith("$1") or t.startswith("$6") or t.startswith("$argon2")),
        int(bool(re.fullmatch(r"[A-Za-z0-9+/]+=*", t) and len(t) >= 24))
    ]


# ─── Carga del modelo ────────────────────────────────────────────────────────

def load_model(path: str = None):
    """Carga el artifact del modelo. Llamar después de los imports."""
    global MODEL, SCALER

    path = path or MODEL_PATH

    if not HAS_JOBLIB:
        print("[!] No se puede cargar modelo: joblib no está instalado")
        return False

    if not os.path.exists(path):
        print(f"[!] Archivo de modelo no encontrado: {path}")
        return False

    try:
        artifact = joblib.load(path)

        if isinstance(artifact, dict):
            MODEL = artifact.get("model")
            SCALER = artifact.get("scaler")
            meta = artifact.get("meta", {})

            if MODEL is None:
                print(f"[!] Artifact inválido: no contiene 'model'")
                return False

            print(f"[+] Modelo cargado: {path}")
            print(f"    Samples entrenados: {meta.get('n_samples_trained', '?')}")
            print(f"    sklearn version: {meta.get('sklearn_version', '?')}")
            print(f"    Clases: {meta.get('class_counts', {})}")
            return True
        else:
            # Fallback: el artifact es directamente el estimador
            MODEL = artifact
            SCALER = None
            print(f"[+] Modelo cargado (sin scaler): {path}")
            return True

    except Exception as e:
        print(f"[!] Error cargando modelo: {e}")
        MODEL = None
        SCALER = None
        return False


# ─── Cargar modelo al importar el módulo ──────────────────────────────────────
load_model()


# ─── Clasificación ────────────────────────────────────────────────────────────

def classify_token_simple(token: str):
    t = token.strip()
    ent = shannon_entropy(t)
    ln = len(t)
    lower = t.lower()

    # quick obvious non-credential checks
    if RE_EMAIL.fullmatch(t) or RE_URL.match(t):
        classification = {"decision": "non_credential", "reason": "email_or_url", "score": 0.99, "type": "email/url"}
    elif lower in WHITELIST:
        classification = {"decision": "non_credential", "reason": "whitelist_common_value", "score": 0.95, "type": "whitelist"}
    else:
        if re.fullmatch(r"[0-9a-fA-F]+", t):
            if ln in HEX_LEN_MAP:
                classification = {"decision": "hash", "reason": f"hex_{HEX_LEN_MAP[ln]}", "score": 0.98, "type": "hex"}
            elif ln >= 24:
                classification = {"decision": "hash", "reason": f"hex_like_len_{ln}", "score": 0.75, "type": "hex_like"}
            else:
                classification = {"decision": "indeterminado", "reason": "short_hex", "score": 0.5, "type": "hex_short"}
        elif t.startswith("$2a$") or t.startswith("$2b$") or t.startswith("$2y$") or t.startswith("$1$") or t.startswith("$6$") or t.startswith("$argon2"):
            classification = {"decision": "hash", "reason": "prefix_hash_format", "score": 0.99, "type": "prefixed_hash"}
        elif re.fullmatch(r"[A-Za-z0-9+/]+=*", t) and ln >= 24:
            if ent > 4.5:
                classification = {"decision": "hash_or_encoded", "reason": "base64_high_entropy", "score": 0.85, "type": "base64"}
            else:
                classification = {"decision": "indeterminado", "reason": "base64_low_entropy", "score": 0.45, "type": "base64"}
        elif RE_DIGIT_ONLY.fullmatch(t):
            classification = {"decision": "non_credential", "reason": "digit_only", "score": 0.9, "type": "digits"}
        else:
            has_lower = bool(re.search(r"[a-z]", t))
            has_upper = bool(re.search(r"[A-Z]", t))
            has_digit = bool(re.search(r"\d", t))
            has_sym = bool(re.search(r"[^\w\s]", t))

            if ln < 12 and (has_lower or has_upper) and (has_digit or has_sym):
                classification = {"decision": "password", "reason": "short_mix_chars_probable_password", "score": 0.85, "type": "short_password"}
            elif ent < 3.8 and (has_lower or has_upper):
                classification = {"decision": "password", "reason": "low_entropy_alpha", "score": 0.88, "type": "password_candidate"}
            elif 0.7 <= hex_ratio(t) < 1.0 and ln >= 16:
                classification = {"decision": "hash_like", "reason": "high_hex_ratio", "score": 0.72, "type": "hex_like"}
            elif ent > 4.8:
                classification = {"decision": "hash_or_strong_password", "reason": "high_entropy", "score": 0.6, "type": "high_entropy"}
            else:
                classification = {"decision": "indeterminado", "reason": "heuristica_inconcluyente", "score": 0.5, "type": "unknown"}

    # ─── ML model enrichment ─────────────────────────────────────────────
    ml_info = {}
    if MODEL is not None:
        try:
            feat = [extract_features(t)]

            # CRÍTICO: aplicar scaler si existe
            if SCALER is not None:
                feat = SCALER.transform(feat)

            pred = MODEL.predict(feat)[0]
            probs = MODEL.predict_proba(feat)[0] if hasattr(MODEL, "predict_proba") else None
            prob = 0.0
            if probs is not None:
                idx = list(MODEL.classes_).index(pred)
                prob = float(probs[idx])
            else:
                prob = 0.6

            ml_info = {"ml_pred": pred, "ml_prob": round(prob, 3)}

            combined = max(
                classification.get("score", 0.5),
                0.6 * classification.get("score", 0.5) + 0.4 * prob
            )
            classification["score"] = round(min(0.999, combined), 3)

            if pred == "non_credential" and prob >= 0.9:
                classification = {
                    "decision": "non_credential",
                    "reason": "ml_confident_non_credential",
                    "score": max(0.95, classification.get("score", 0.5)),
                    "type": "ml_override"
                }
            else:
                classification["ml_suggestion"] = ml_info

        except Exception as e:
            ml_info = {"ml_error": str(e)}
            classification["ml_suggestion"] = ml_info

    return classification


def extract_kv_around(line: str, token_span_start: int, token_span_end: int):
    """Intenta extraer clave/valor cercanos."""
    start = max(0, token_span_start - 80)
    end = min(len(line), token_span_end + 80)
    window = line[start:end]

    kv = {}
    for m in re.finditer(r'([A-Za-z0-9_\-\.]{3,20})\s*[:=]\s*["\']?([^\s"\'\,;]{1,200})["\']?', window):
        k = m.group(1).lower()
        v = m.group(2)
        kv[k] = v

    if 'user' not in kv and 'username' not in kv and 'login' not in kv:
        musr = re.search(r'(?:user(?:name)?|login)[:=]\s*([A-Za-z0-9_\-\.]{1,64})', window, re.IGNORECASE)
        if musr:
            kv['user'] = musr.group(1)

    return kv


def decide_final_verdict(classification: dict, pattern_category: str, pattern_name: str, token: str, kv: dict, context_lines: list):
    score = classification.get("score", 0.5)
    decision = classification.get("decision", "indeterminado")
    reasons = [classification.get("reason", "")]

    if pattern_category == 'filename' or pattern_name.startswith('filename'):
        return {"verdict": "suspicious_filename", "score": 0.9, "explain": "filename_keyword", "action": "review"}

    if decision == "non_credential":
        return {"verdict": "false_positive", "score": score, "explain": ";".join(reasons), "action": "ignore"}

    if any(k for k in kv.keys() if 'pass' in k or k in ('pwd', 'password', 'passwd', 'contraseña', 'clave')):
        return {"verdict": "likely_credential", "score": min(0.98, score + 0.15), "explain": "kv_nearby_password_field", "action": "alert"}

    if any(k for k in kv.keys() if k in ('user', 'username', 'login', 'usuario')):
        return {"verdict": "likely_credential", "score": min(0.95, score + 0.12), "explain": "username_nearby", "action": "alert"}

    if decision in ("hash",) and score >= 0.8:
        return {"verdict": "likely_hash", "score": score, "explain": ";".join(reasons), "action": "alert_hash"}

    if decision in ("hash_or_strong_password", "hash_or_encoded") and score < 0.8:
        return {"verdict": "uncertain", "score": score, "explain": "high_entropy_no_context", "action": "review"}

    if decision == "password" and score >= 0.75:
        return {"verdict": "likely_credential", "score": score, "explain": "weak_password_pattern", "action": "alert"}

    return {"verdict": "uncertain", "score": score, "explain": "fallback_conservative", "action": "review"}


def enrich_match(category: str, pattern_name: str, token: str, line: str, token_start: int, token_end: int, share: str, file_path: str, line_num: int, context_lines: list):
    classification = classify_token_simple(token)
    kv = extract_kv_around(line, token_start, token_end)
    final = decide_final_verdict(classification, category, pattern_name, token, kv, context_lines)

    enriched = {
        "share": share,
        "file": file_path,
        "line_num": line_num,
        "pattern_category": category,
        "pattern_name": pattern_name,
        "token": token,
        "token_span": [token_start, token_end],
        "token_length": len(token),
        "token_entropy": round(shannon_entropy(token), 4),
        "classification": classification,
        "kv_nearby": kv,
        "context_lines": context_lines,
        "final_verdict": final["verdict"],
        "final_score": round(final["score"], 3),
        "final_explain": final["explain"],
        "final_action": final["action"]
    }
    return enriched


# CLI quick test
if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) >= 6:
        cat = sys.argv[1]
        pname = sys.argv[2]
        token = sys.argv[3]
        share = sys.argv[4]
        filepath = sys.argv[5]
        line = sys.stdin.read() or ""
        idx = line.find(token)
        start = idx if idx >= 0 else 0
        end = start + len(token)
        out = enrich_match(cat, pname, token, line, start, end, share, filepath, 0, [])
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print("Uso: cat file | python nxc_credential_detector.py <category> <pattern> <token> <share> <file>")
