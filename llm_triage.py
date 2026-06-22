#!/usr/bin/env python3
"""
llm_triage.py — Prototipo de capa LLM de triaje de incidentes.

PRUEBA DE CONCEPTO. No forma parte del pipeline principal y no lo
modifica. Es un script independiente y a prueba de fallos: si no hay
clave de API configurada, avisa y termina sin romper nada.

Idea
----
La Capa 3 del sistema agrupa miles de alertas en un puñado de
comunidades. Este prototipo demuestra que esas comunidades son una
entrada adecuada para que un modelo de lenguaje genere un triaje
legible: tipo de incidente probable, severidad estimada, acciones
sugeridas y un resumen narrativo.

Punto importante de diseño: al LLM NO se le envían las alertas crudas,
sino un RESUMEN ESTRUCTURADO de la comunidad (decoders, reglas,
entidades, ventana temporal, volumen). Es decir, el LLM se beneficia
del trabajo de correlación previo de las Capas 2 y 3. Esto es lo que
el prototipo pretende ilustrar.

Proveedor
---------
Por defecto usa Google AI Studio (Gemini Flash), cuyo nivel gratuito
no requiere tarjeta. Mediante variables de entorno puede apuntar a
cualquier API compatible con OpenAI (Groq, OpenRouter, etc.) sin
cambiar el código.

Variables de entorno:
  LLM_PROVIDER   "gemini" (defecto) o "openai-compatible"
  LLM_API_KEY    la clave de API (obligatoria para ejecutar de verdad)
  LLM_MODEL      modelo a usar (defecto: gemini-2.5-flash / segun proveedor)
  LLM_BASE_URL   solo para "openai-compatible": URL base del endpoint
                 p.ej. https://api.groq.com/openai/v1

Uso:
  # triaje de las 3 comunidades de mayor volumen
  python3 llm_triage.py --top 3

  # triaje de una comunidad concreta
  python3 llm_triage.py --community 137

  # modo simulado: no llama a la API, genera un triaje de muestra
  # (sirve para probar el formato sin clave)
  python3 llm_triage.py --community 137 --dry-run

Salida:
  lab_state/llm_triage/community_<id>.json   un fichero por comunidad
  lab_state/llm_triage/_resumen.json         indice de lo generado
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parent))
from anonymization import maybe_load, DEFAULT_MAP_PATH


IN = Path("lab_state/real_alerts_incidents.parquet")
OUT_DIR = Path("lab_state/llm_triage")


# ----------------------------------------------------------------------
# Utilidades de lectura del Parquet
# ----------------------------------------------------------------------
def _iter(v):
    if v is None:
        return
    if isinstance(v, (list, tuple, np.ndarray)):
        for x in v:
            if x:
                yield x
    elif isinstance(v, str) and v:
        yield v


def build_community_context(df: pd.DataFrame, community_id: int,
                            anon=None) -> dict:
    """Construye el resumen estructurado de una comunidad. Este dict es
    lo que se envia al LLM: contexto correlacionado, NO alertas crudas.

    Los `usuarios` del contexto provienen de `entity_users` del parquet,
    que ya esta anonimizado en origen (extract_indexer.py). Las
    descripciones de regla son texto libre que puede contener nombres
    de usuario embebidos; si `anon` esta cargado se anonimizan tambien
    aqui para que el LLM NO reciba ningun nombre real.
    """
    sub = df[df["community_id"] == community_id]
    if sub.empty:
        raise ValueError(f"La comunidad {community_id} no existe")

    ips, users, hosts = Counter(), Counter(), Counter()
    rules, decoders = Counter(), Counter()
    tactics, techniques = Counter(), Counter()
    descriptions = Counter()
    for _, r in sub.iterrows():
        for x in _iter(r.get("entity_ips")):    ips[str(x)] += 1
        for x in _iter(r.get("entity_users")):  users[str(x)] += 1
        for x in _iter(r.get("entity_hosts")):  hosts[str(x)] += 1
        rules[str(r.get("rule.id"))] += 1
        decoders[str(r.get("decoder.name"))] += 1
        desc = r.get("rule.description")
        if isinstance(desc, str) and desc:
            if anon is not None:
                desc = anon.anonymize_text(desc)
            descriptions[desc] += 1
        for campo, cont in (("rule.mitre.tactic", tactics),
                            ("rule.mitre.technique", techniques)):
            v = r.get(campo)
            for x in _iter(v if isinstance(v, (list, np.ndarray)) else
                           (v.split(",") if isinstance(v, str) else None)):
                x = str(x).strip()
                if x:
                    cont[x] += 1

    first = sub["first_seen"].min()
    last = sub["last_seen"].max()
    dur = (last - first).total_seconds() if pd.notna(first) and pd.notna(last) else 0

    nivel_max = pd.to_numeric(sub["rule.level"], errors="coerce").max()

    return {
        "community_id": int(community_id),
        "n_filas": int(len(sub)),
        "n_alertas_originales": int(sub["count"].sum()),
        "n_clusters_capa2": int(sub["cluster_id"].nunique()),
        "ventana_inicio": first.isoformat() if pd.notna(first) else None,
        "ventana_fin": last.isoformat() if pd.notna(last) else None,
        "duracion_segundos": int(dur),
        "nivel_severidad_max": int(nivel_max) if pd.notna(nivel_max) else None,
        "decoders": [d for d, _ in decoders.most_common()],
        "es_cross_source": len(decoders) > 1,
        "reglas_top": [{"id": r, "n": n} for r, n in rules.most_common(8)],
        "descripciones_reglas": [d for d, _ in descriptions.most_common(6)],
        "usuarios": [u for u, _ in users.most_common(10)],
        "ips": [i for i, _ in ips.most_common(10)],
        "hosts": [h for h, _ in hosts.most_common(10)],
        "mitre_tacticas": [t for t, _ in tactics.most_common()],
        "mitre_tecnicas": [t for t, _ in techniques.most_common()],
    }


# ----------------------------------------------------------------------
# Construccion del prompt
# ----------------------------------------------------------------------
SYSTEM_PROMPT = (
    "Eres un analista de seguridad en un centro de operaciones (SOC). "
    "Recibes el resumen de una COMUNIDAD de alertas: un conjunto de "
    "alertas que un sistema de correlacion ha agrupado porque comparten "
    "entidades (usuarios, direcciones IP, equipos) y proximidad temporal. "
    "Tu tarea es hacer un triaje inicial de esa comunidad. "
    "No dispones de las alertas en bruto, solo del resumen agregado; "
    "razona unicamente sobre la informacion proporcionada y no inventes "
    "datos.\n\n"
    "Calibra el triaje con prudencia. Ten en cuenta estas senales:\n"
    "- La agrupacion la hace un algoritmo de clustering, no un analista. "
    "Que muchos usuarios sin relacion aparente caigan en la misma "
    "comunidad puede deberse a que su actividad es similar (mismos tipos "
    "de evento), no necesariamente a un ataque coordinado.\n"
    "- Las tacticas y tecnicas MITRE provienen de las reglas de Wazuh "
    "que se dispararon, no de un analisis del incidente; son orientativas.\n"
    "- Una severidad alta solo esta justificada si hay indicios claros: "
    "nivel de regla elevado, correlacion entre varias fuentes distintas, "
    "o entidades inequivocamente sospechosas. Un unico tipo de fuente y "
    "un nivel de regla bajo o medio raramente justifican severidad alta.\n"
    "- La confianza debe reflejar la solidez de la evidencia. Si el "
    "cuadro es ambiguo o compatible con actividad rutinaria, la confianza "
    "es baja, aunque el tipo de incidente que plantees sea grave.\n"
    "Es preferible un triaje prudente y matizado que uno alarmista. "
    "Si la informacion es insuficiente para una conclusion firme, "
    "indicalo y reflejalo en el campo de confianza.\n\n"
    "Responde SIEMPRE en español y EXCLUSIVAMENTE con un objeto JSON "
    "valido, sin texto antes ni despues, sin bloques de codigo Markdown."
)

ESQUEMA_SALIDA = """Devuelve un objeto JSON con exactamente estos campos:
{
  "tipo_incidente": "cadena breve, p.ej. 'acceso sospechoso a O365', 'actividad de mantenimiento benigna', 'posible movimiento lateral'",
  "severidad": "uno de: informativa, baja, media, alta, critica",
  "es_probablemente_benigno": true o false,
  "entidades_clave": ["lista de las entidades mas relevantes para investigar"],
  "factores_de_incertidumbre": ["lista de 1 a 3 razones por las que el triaje podria estar equivocado, p.ej. 'la agrupacion de muchos usuarios podria ser un artefacto del clustering'; lista vacia solo si la evidencia es muy solida"],
  "acciones_recomendadas": ["lista de 2 a 4 acciones concretas de investigacion o respuesta"],
  "confianza": "uno de: baja, media, alta",
  "resumen_narrativo": "un parrafo de 2 a 4 frases, en lenguaje natural, que un analista pueda leer de un vistazo: que parece haber pasado, por que, y que mirar primero"
}"""


def build_user_prompt(ctx: dict) -> str:
    return (
        "Resumen de la comunidad de alertas a triar:\n\n"
        + json.dumps(ctx, ensure_ascii=False, indent=2)
        + "\n\n"
        + ESQUEMA_SALIDA
    )


# ----------------------------------------------------------------------
# Clientes de proveedor LLM
# ----------------------------------------------------------------------
import time

# Errores HTTP que merece la pena reintentar: el servidor esta
# temporalmente ocupado (503), saturado (502/504) o se ha alcanzado el
# limite de peticiones por minuto (429). Son transitorios.
_RETRY_STATUS = {429, 502, 503, 504}


_HTTP_DEADLINE_S = 240  # tope total por llamada (request + esperas)


def _http_post(url: str, payload: dict, headers: dict, timeout: int = 60,
               max_intentos: int = 3, deadline_s: int = _HTTP_DEADLINE_S):
    """POST con reintentos ante errores transitorios. Entre intentos
    espera de forma creciente (2 s, 4 s, 8 s ...).

    Tope total acumulado: si la suma de timeouts + esperas supera
    deadline_s segundos, se aborta con el ultimo error en lugar de
    seguir reintentando. Evita que una comunidad bloquee el triaje
    durante minutos si el proveedor se queda colgado."""
    data = json.dumps(payload).encode("utf-8")
    ultimo_error = None
    start = time.monotonic()
    for intento in range(1, max_intentos + 1):
        if time.monotonic() - start > deadline_s:
            print(f"(deadline {deadline_s}s superado, abortando)",
                  end=" ", flush=True)
            break
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            ultimo_error = e
            if e.code in _RETRY_STATUS and intento < max_intentos:
                espera = 2 ** intento
                # no esperes si ya estas pasado del deadline
                if time.monotonic() - start + espera > deadline_s:
                    print(f"(HTTP {e.code}, sin margen para reintentar)",
                          end=" ", flush=True)
                    break
                print(f"(HTTP {e.code}, reintento {intento}/"
                      f"{max_intentos - 1} en {espera}s)",
                      end=" ", flush=True)
                time.sleep(espera)
                continue
            raise
        except urllib.error.URLError as e:
            # fallos de red transitorios
            ultimo_error = e
            if intento < max_intentos:
                espera = 2 ** intento
                if time.monotonic() - start + espera > deadline_s:
                    print("(error de red, sin margen para reintentar)",
                          end=" ", flush=True)
                    break
                print(f"(error de red, reintento en {espera}s)",
                      end=" ", flush=True)
                time.sleep(espera)
                continue
            raise
    if ultimo_error:
        raise ultimo_error


def call_gemini(system: str, user: str, api_key: str, model: str) -> str:
    """Llama a la API de Google AI Studio (Gemini). Devuelve el texto
    de la respuesta del modelo."""
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={api_key}")
    payload = {
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }
    resp = _http_post(url, payload, {"Content-Type": "application/json"})
    # Caso 1: el prompt entero se bloqueo aguas arriba (filtro de
    # seguridad de Gemini sobre el system+user). No hay candidates.
    pf = resp.get("promptFeedback") or {}
    block = pf.get("blockReason")
    if block:
        raise RuntimeError(
            f"Gemini bloqueo el prompt: blockReason={block}. "
            "Revisa el contenido del contexto enviado.")
    # Caso 2: hubo candidato pero no terminó normalmente (SAFETY,
    # MAX_TOKENS, RECITATION...). content.parts puede estar vacio.
    cand = (resp.get("candidates") or [{}])[0]
    finish = cand.get("finishReason")
    parts = (cand.get("content") or {}).get("parts") or [{}]
    text = parts[0].get("text", "")
    if not text:
        if finish and finish != "STOP":
            raise RuntimeError(
                f"Gemini devolvio respuesta vacia: finishReason={finish}.")
        # texto vacio sin razon — defensivo: propagar como error en vez
        # de devolver "" y dejar que el parser JSON crashee mas tarde
        # sin pista del motivo.
        raise RuntimeError(
            "Gemini devolvio respuesta vacia sin finishReason.")
    return text


def call_openai_compatible(system: str, user: str, api_key: str,
                           model: str, base_url: str) -> str:
    """Llama a cualquier API compatible con OpenAI (Groq, OpenRouter,
    etc.). Devuelve el texto de la respuesta del modelo."""
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    resp = _http_post(url, payload, headers)
    return resp["choices"][0]["message"]["content"]


def call_llm(system: str, user: str) -> str:
    """Despacha a un proveedor u otro segun las variables de entorno.
    Lanza RuntimeError si falta configuracion."""
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    api_key = os.environ.get("LLM_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "No hay clave de API. Define la variable de entorno "
            "LLM_API_KEY (ver instrucciones al inicio del script) o usa "
            "--dry-run para probar el formato sin llamar al modelo.")

    if provider == "gemini":
        model = os.environ.get("LLM_MODEL", "gemini-2.5-flash")
        return call_gemini(system, user, api_key, model)
    elif provider == "openai-compatible":
        base_url = os.environ.get("LLM_BASE_URL", "").strip()
        if not base_url:
            raise RuntimeError(
                "Con LLM_PROVIDER=openai-compatible hay que definir "
                "LLM_BASE_URL (p.ej. https://api.groq.com/openai/v1).")
        model = os.environ.get("LLM_MODEL", "llama-3.3-70b-versatile")
        return call_openai_compatible(system, user, api_key, model, base_url)
    else:
        raise RuntimeError(f"LLM_PROVIDER desconocido: {provider}")


# ----------------------------------------------------------------------
# Modo simulado (sin API)
# ----------------------------------------------------------------------
def fake_triage(ctx: dict) -> dict:
    """Genera un triaje de muestra SIN llamar a ningun LLM. Sirve para
    probar el formato de salida del prototipo cuando no hay clave de API.
    Aplica heuristicas muy simples; NO es analisis real."""
    nivel = ctx.get("nivel_severidad_max") or 0
    cross = ctx.get("es_cross_source", False)
    n_alertas = ctx.get("n_alertas_originales", 0)
    svc = any(u.lower().startswith(("user:svc-", "svc-"))
              for u in ctx.get("usuarios", []))

    if svc and not cross:
        sev, benigno, tipo = "informativa", True, \
            "actividad de cuentas de servicio (probable mantenimiento)"
    elif cross and nivel >= 10:
        sev, benigno, tipo = "alta", False, \
            "actividad cross-source con reglas de severidad elevada"
    elif cross:
        sev, benigno, tipo = "media", False, \
            "actividad correlacionada entre varias fuentes"
    else:
        sev, benigno, tipo = "baja", False, "actividad de una sola fuente"

    entidades = (ctx.get("usuarios", [])[:3]
                 + ctx.get("ips", [])[:3])
    incertidumbre = []
    if len(ctx.get("usuarios", [])) > 4:
        incertidumbre.append(
            "la comunidad agrupa muchos usuarios sin relacion aparente, "
            "lo que podria ser un artefacto del clustering y no un "
            "incidente coordinado")
    if not cross:
        incertidumbre.append(
            "la actividad proviene de una sola fuente, lo que limita la "
            "evidencia disponible")
    return {
        "tipo_incidente": tipo,
        "severidad": sev,
        "es_probablemente_benigno": benigno,
        "entidades_clave": entidades,
        "factores_de_incertidumbre": incertidumbre,
        "acciones_recomendadas": [
            "Revisar las alertas originales de la comunidad en el "
            "Dashboard filtrando por community_id",
            "Verificar si las entidades implicadas corresponden a "
            "actividad esperada",
        ],
        "confianza": "baja",
        "resumen_narrativo": (
            f"Comunidad de {ctx['n_filas']} filas que agrupan "
            f"{n_alertas} alertas originales, "
            f"{'con' if cross else 'sin'} correlacion entre varias "
            f"fuentes ({', '.join(ctx.get('decoders', []))}). "
            "Triaje generado en modo simulado sin modelo de lenguaje; "
            "los valores son orientativos y deben confirmarse con un "
            "analisis real."
        ),
        "_modo": "simulado (sin LLM)",
    }


# ----------------------------------------------------------------------
# Parseo robusto de la respuesta del LLM
# ----------------------------------------------------------------------
def parse_llm_json(texto: str) -> dict:
    """Intenta parsear la respuesta del LLM como JSON. Tolera que el
    modelo haya envuelto el JSON en un bloque de codigo Markdown."""
    t = texto.strip()
    if t.startswith("```"):
        # quitar la primera linea (```json) y el cierre
        t = t.split("\n", 1)[1] if "\n" in t else t
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return json.loads(t.strip())


# ----------------------------------------------------------------------
# Principal
# ----------------------------------------------------------------------
def triage_community(df, community_id, dry_run, anon=None):
    ctx = build_community_context(df, community_id, anon=anon)
    if dry_run:
        return ctx, fake_triage(ctx)

    system = SYSTEM_PROMPT
    user = build_user_prompt(ctx)
    try:
        raw = call_llm(system, user)
    except RuntimeError as e:
        # respuesta bloqueada o vacia con razon explicita: lo guardamos
        # como triaje fallido en vez de propagar para no perder la
        # trazabilidad de las comunidades restantes.
        triage = {"_error": str(e), "_respuesta_cruda": "", "_modo": "llm"}
        return ctx, triage
    try:
        triage = parse_llm_json(raw)
    except (json.JSONDecodeError, ValueError) as e:
        triage = {
            "_error": f"La respuesta del LLM no es JSON valido: {e}",
            "_respuesta_cruda": raw[:1000],
        }
    triage["_modo"] = "llm"
    return ctx, triage


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(IN),
                    help="parquet de comunidades (salida de la Capa 3)")
    ap.add_argument("--community", type=int, default=None,
                    help="triar una comunidad concreta por su id")
    ap.add_argument("--top", type=int, default=None,
                    help="triar las N comunidades de mayor volumen")
    ap.add_argument("--dry-run", action="store_true",
                    help="no llama a la API; genera un triaje simulado "
                         "para probar el formato")
    ap.add_argument("--user-alias-map", default=str(DEFAULT_MAP_PATH),
                    help="mapa de anonimizacion; si existe, se aplica a "
                         "las descripciones de regla del contexto para "
                         "que el LLM no reciba nombres de usuario reales")
    args = ap.parse_args()

    anon = maybe_load(args.user_alias_map)
    if anon is not None:
        print(f"[anon] anonimizando descripciones del contexto con "
              f"{args.user_alias_map} ({len(anon.forward)} usuarios)")

    src = Path(args.input)
    if not src.exists():
        raise SystemExit(f"No existe {src}. Corre la Capa 3 primero.")

    df = pd.read_parquet(src)
    valid = df[df["community_id"] >= 0]
    if valid.empty:
        raise SystemExit("El parquet no tiene comunidades (community_id>=0).")

    # decidir qué comunidades triar
    if args.community is not None:
        ids = [args.community]
    elif args.top is not None:
        ids = (valid.groupby("community_id")["count"].sum()
               .sort_values(ascending=False).head(args.top).index.tolist())
    else:
        # por defecto, las 3 mayores
        ids = (valid.groupby("community_id")["count"].sum()
               .sort_values(ascending=False).head(3).index.tolist())

    # comprobacion temprana de configuracion (salvo dry-run)
    if not args.dry_run and not os.environ.get("LLM_API_KEY", "").strip():
        print("=" * 64)
        print("  No hay clave de API configurada (LLM_API_KEY).")
        print("  Este prototipo necesita una clave para llamar al modelo.")
        print()
        print("  Como obtener una clave gratuita de Google AI Studio:")
        print("   1. Entra en  https://aistudio.google.com/apikey")
        print("   2. Inicia sesion con una cuenta de Google")
        print("   3. Pulsa 'Create API key' y copia la clave")
        print("   4. Exportala antes de ejecutar:")
        print("        export LLM_API_KEY='tu-clave-aqui'")
        print()
        print("  O bien prueba el formato sin clave:")
        print("        python3 llm_triage.py --community "
              f"{ids[0]} --dry-run")
        print("=" * 64)
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    modo = "SIMULADO (sin LLM)" if args.dry_run else \
        f"LLM ({os.environ.get('LLM_PROVIDER', 'gemini')})"
    print(f"Triaje de {len(ids)} comunidad(es) — modo: {modo}\n")

    indice = []
    for cid in ids:
        print(f"  comunidad #{cid} ...", end=" ", flush=True)
        try:
            ctx, triage = triage_community(df, cid, args.dry_run, anon=anon)
        except Exception as e:
            print(f"ERROR: {e}")
            continue
        registro = {
            "community_id": int(cid),
            "generado": datetime.now(timezone.utc).isoformat(),
            "contexto": ctx,
            "triaje": triage,
        }
        path = OUT_DIR / f"community_{cid}.json"
        path.write_text(json.dumps(registro, ensure_ascii=False, indent=2),
                        encoding="utf-8")
        sev = triage.get("severidad", "?")
        tipo = triage.get("tipo_incidente", "?")
        print(f"[{sev}] {tipo}")
        indice.append({
            "community_id": int(cid),
            "severidad": sev,
            "tipo_incidente": tipo,
            "fichero": path.name,
        })

    (OUT_DIR / "_resumen.json").write_text(
        json.dumps({"modo": modo,
                    "generado": datetime.now(timezone.utc).isoformat(),
                    "comunidades": indice},
                   ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"\nResultados en {OUT_DIR}/")


if __name__ == "__main__":
    main()
