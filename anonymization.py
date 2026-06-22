"""
anonymization.py - Anonimizacion biyectiva de nombres de usuario.

Por que existe
--------------
Los nombres de usuario (lab.user1, tfm.s06.victim1, LABCORP\\admin, ...) son
informacion identificadora directa. Para poder usar el sistema sobre
datos reales sin exponer identidades a:
  - parquets en disco (lab_state/*.parquet),
  - indices del Indexer (wazuh-correlation-*),
  - contexto enviado al LLM (Gemini, Groq, etc.),
  - figuras y casos de comunidad de la memoria,

se sustituye cada usuario por un alias estable del tipo
`user_NNNN_anonymized`. El mapa se persiste en disco para que el mismo
usuario reciba siempre el mismo alias entre runs, lo cual preserva la
correlacion: dos filas que comparten 'lab.user1' siguen compartiendo
'user_0001_anonymized' y el grafo de la Capa 3 las conecta exactamente
igual.

Las direcciones IP y los hostnames NO se anonimizan (decision del
proyecto): identifican activos de red, no personas, y son utiles para
la investigacion del SOC sin levantar problema de privacidad equivalente.

Que NO hace este modulo
-----------------------
- No es cifrado: el mapa local es reversible. Quien tenga acceso al
  fichero del mapa puede revertir los aliases. Esto es deliberado: el
  mapa permite auditar internamente y resolver casos cuando hace falta.
  La proteccion es "datos en transito y en almacenamiento secundario",
  no "datos en reposo en el lab".
- No oculta IPs ni hostnames.
- No sustituye dominios completos: 'lab.user1@labcorp.local' pasa a
  'user_0001_anonymized' (no se conserva el dominio), porque la forma
  canonica que produce normalize.norm_user ya descarta los dominios
  organizacionales.

Como integra con el pipeline
----------------------------
- Capa 1 (extract_indexer / extract_real): tras extraer entidades con
  normalize.norm_user, se aplica `anonymize` a cada usuario canonico
  antes de guardar el parquet. La columna `entity_users` del parquet
  ya queda con aliases.
- Capa 2/3: trabajan sobre el parquet ya anonimizado; el clustering y
  el grafo no distinguen alias de nombre real, solo necesitan que el
  identificador sea estable.
- Evaluacion (verify_scenarios, comparar_clustering, barrido_tau):
  cargan el mapa y resuelven las entidades del ground_truth.jsonl al
  hacer el matching contra el parquet anonimizado.
- Persistencia al Indexer (push_to_indexer): aplica `anonymize_raw_user`
  a los campos `data.*User*`, `data.*user`, `data.*srcuser`, etc. crudos,
  y `anonymize_text` a `rule.description`.
- LLM (llm_triage): el contexto de comunidad ya recibe entity_users
  anonimizados desde el parquet; ademas se aplica `anonymize_text` a
  las descripciones de regla del contexto.

Uso minimo
----------
    from anonymization import UserAnonymizer

    anon = UserAnonymizer("lab_state/user_alias_map.json")
    a1 = anon.anonymize("user:lab.user1")             # -> "user:user_0001_anonymized"
    a2 = anon.anonymize("user:lab.user1")             # idempotente
    s = anon.anonymize_set({"user:lab.user1", "user:asmith"})
    anon.save()                                  # persistir

    # Reversa para auditoria interna:
    raw = anon.reverse("user:user_0001_anonymized")  # -> "user:lab.user1"

Tests rapidos
-------------
    python3 anonymization.py        # ejecuta el bloque __main__ con assertions
"""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Iterable, Optional


DEFAULT_MAP_PATH = Path("lab_state/user_alias_map.json")


class UserAnonymizer:
    """Mapa biyectivo usuario_canonico <-> alias_anonimizado.

    Acepta entradas con o sin prefijo 'user:' y preserva el prefijo en la
    salida. Genera aliases del estilo 'user_NNNN_anonymized' (zero-padding
    a 4 digitos por defecto, suficiente para >9999 usuarios distintos sin
    cambiar el ancho del alias).

    El mapa se persiste en JSON con permisos 600 y se reutiliza entre
    runs para que el mismo usuario reciba siempre el mismo alias. Esto
    es lo que mantiene la correlacion estable: si dos runs comparten
    usuarios, los aliases coinciden.

    Thread-safe: protegido con un lock para que la asignacion de nuevos
    aliases no se duplique cuando varias capas piden alias en paralelo.
    """

    ALIAS_PREFIX = "user_"
    ALIAS_SUFFIX = "_anonymized"
    ALIAS_PAD = 4  # user_0001_anonymized .. user_9999_anonymized

    # Patron que detecta un alias ya anonimizado. Se usa para evitar
    # re-anonimizar valores que ya pasaron por aqui (idempotencia
    # defensiva: si por error alguien aplica anonymize a un alias,
    # devolvemos el alias intacto en vez de crear 'user_0002_anonymized'
    # como sinonimo de 'user_0001_anonymized').
    _ALIAS_RX = re.compile(
        r"^(?:user:)?" + re.escape(ALIAS_PREFIX) + r"\d+" +
        re.escape(ALIAS_SUFFIX) + r"$"
    )

    def __init__(self, map_path: Optional[str | Path] = None):
        self.map_path = Path(map_path) if map_path else None
        # canonico (sin prefijo, en minusculas) -> alias (sin prefijo)
        self.forward: dict[str, str] = {}
        # alias (sin prefijo) -> canonico (sin prefijo)
        self.reverse_map: dict[str, str] = {}
        self._lock = threading.Lock()
        self._next_id = 1
        if self.map_path and self.map_path.exists():
            self.load()

    # ------------------------------------------------------------------
    # API principal
    # ------------------------------------------------------------------
    def anonymize(self, value: Optional[str]) -> Optional[str]:
        """Devuelve el alias para un usuario canonico (con o sin prefijo
        'user:'). Si es nuevo, lo registra. Si ya es un alias, lo deja
        intacto. Si no es string utilizable, lo devuelve tal cual.
        """
        if not isinstance(value, str) or not value:
            return value
        if self._ALIAS_RX.match(value):
            return value  # ya anonimizado, no re-anonimizar
        canonical, had_prefix = self._strip_prefix(value)
        canonical = canonical.strip().lower()
        if not canonical:
            return value
        with self._lock:
            alias = self.forward.get(canonical)
            if alias is None:
                alias = self._format_alias(self._next_id)
                self._next_id += 1
                self.forward[canonical] = alias
                self.reverse_map[alias] = canonical
        return f"user:{alias}" if had_prefix else alias

    def anonymize_set(self, values):
        """Anonimiza un set / list / np.ndarray de usuarios canonicos
        preservando el tipo de contenedor. Tolera None/listas vacias."""
        if values is None:
            return values
        # numpy.ndarray no se importa para no obligar a numpy en este
        # modulo; se trata por su interfaz iterable.
        if isinstance(values, set):
            return {self.anonymize(v) for v in values if v is not None}
        if isinstance(values, (list, tuple)):
            cls = type(values)
            return cls(self.anonymize(v) for v in values if v is not None)
        # cualquier otro iterable -> list
        try:
            iter(values)
            return [self.anonymize(v) for v in values if v is not None]
        except TypeError:
            return self.anonymize(values)

    def anonymize_raw_user(self, raw_value, normalizer=None):
        """Toma un valor CRUDO de las alertas Wazuh (p.ej.
        'LABCORP\\lab.user1', 'lab.user1@labcorp.local', 'VSPHERE.LOCAL\\svc-x')
        y devuelve su alias plano (sin prefijo 'user:'), listo para
        sustituir el campo `data.*` original antes del push al Indexer.

        Si el valor no parsea como un usuario reconocible, lo devuelve
        sin cambios. Si no esta registrado en el mapa, lo registra al
        vuelo (mismo criterio que `anonymize`).

        Parametros
        ----------
        raw_value :
            Valor crudo, posiblemente con dominio o backslash.
        normalizer : callable, opcional
            Funcion que toma el valor crudo y devuelve la forma canonica
            ('user:lab.user1' o None). Por defecto se importa
            `normalize.norm_user` para no crear dependencia ciclica en
            tiempo de import.
        """
        if not isinstance(raw_value, str) or not raw_value:
            return raw_value
        if self._ALIAS_RX.match(raw_value):
            return raw_value
        if normalizer is None:
            from normalize import norm_user as normalizer
        canon = normalizer(raw_value)
        if not canon:
            return raw_value
        canon_no_prefix = canon[5:] if canon.startswith("user:") else canon
        canon_no_prefix = canon_no_prefix.strip().lower()
        with self._lock:
            alias = self.forward.get(canon_no_prefix)
            if alias is None:
                alias = self._format_alias(self._next_id)
                self._next_id += 1
                self.forward[canon_no_prefix] = alias
                self.reverse_map[alias] = canon_no_prefix
        return alias

    def anonymize_text(self, text, extra_aliases_map: dict | None = None):
        """Reemplaza, en un texto libre (p.ej. rule.description), las
        ocurrencias de los usuarios YA registrados en el mapa por sus
        alias. NO auto-registra: el riesgo de que una palabra del texto
        coincida casualmente con un username y se inflen aliases falsos
        no compensa.

        Reconoce tres variantes habituales del username en texto:
            - 'lab.user1'                  (palabra suelta)
            - 'lab.user1@<dominio>'        (Office 365, vCenter description)
            - '<dominio>\\lab.user1'        (NetBIOS / Windows)

        El reemplazo es case-insensitive. Si dos canonicos solapan
        (p.ej. 'adm' y 'admin'), se procesa primero el mas largo para
        evitar matches parciales.

        `extra_aliases_map` permite pasar un mapa adicional ad-hoc en
        caso de que el caller quiera incluir aliases no registrados
        todavia en el mapa principal (poco frecuente).
        """
        if not isinstance(text, str) or not text:
            return text
        sources: dict[str, str] = dict(self.forward)
        if extra_aliases_map:
            sources.update(extra_aliases_map)
        if not sources:
            return text
        # ordenar por longitud desc para no comerse prefijos comunes
        for canonical in sorted(sources.keys(), key=len, reverse=True):
            alias = sources[canonical]
            esc = re.escape(canonical)
            # tres patrones; orden importa: primero la forma 'DOM\user'
            # y 'user@dom' (mas especificas) antes que 'user' suelto.
            patterns = [
                # DOMINIO\user (Windows / NetBIOS)
                r"\b[\w.-]+\\" + esc + r"\b",
                # user@dominio
                r"\b" + esc + r"@[\w][\w.-]*",
                # user a secas con word boundary
                r"(?<![\w.-])" + esc + r"(?![\w.-])",
            ]
            for pat in patterns:
                text = re.sub(pat, alias, text, flags=re.IGNORECASE)
        return text

    def lookup(self, value: Optional[str]) -> Optional[str]:
        """Como `anonymize` pero NO auto-registra: si el canonico no
        esta en el mapa, devuelve None. Pensado para la fase de
        evaluacion (verify_scenarios, etc.), que solo debe consultar
        aliases ya creados por el extractor, nunca crearlos."""
        if not isinstance(value, str) or not value:
            return None
        if self._ALIAS_RX.match(value):
            return value
        canon, had_prefix = self._strip_prefix(value)
        canon = canon.strip().lower()
        alias = self.forward.get(canon)
        if alias is None:
            return None
        return f"user:{alias}" if had_prefix else alias

    def lookup_raw(self, raw_value, normalizer=None) -> Optional[str]:
        """Como `anonymize_raw_user` pero NO auto-registra. Devuelve el
        alias plano (sin prefijo) si el usuario esta en el mapa, o None
        en caso contrario. Usado en la fase de evaluacion para resolver
        las entidades del ground_truth sin contaminar el mapa."""
        if not isinstance(raw_value, str) or not raw_value:
            return None
        if self._ALIAS_RX.match(raw_value):
            return raw_value
        if normalizer is None:
            from normalize import norm_user as normalizer
        canon = normalizer(raw_value)
        if not canon:
            return None
        canon_no_prefix = canon[5:] if canon.startswith("user:") else canon
        return self.forward.get(canon_no_prefix.strip().lower())

    def reverse(self, alias: Optional[str]) -> Optional[str]:
        """Dado un alias (con o sin prefijo 'user:'), devuelve el
        usuario canonico original. Si el alias no esta en el mapa,
        devuelve el valor original."""
        if not isinstance(alias, str) or not alias:
            return alias
        a, had_prefix = self._strip_prefix(alias)
        canon = self.reverse_map.get(a)
        if canon is None:
            return alias
        return f"user:{canon}" if had_prefix else canon

    def known_users(self) -> set[str]:
        """Conjunto de usuarios canonicos registrados (sin prefijo)."""
        return set(self.forward.keys())

    # ------------------------------------------------------------------
    # Persistencia
    # ------------------------------------------------------------------
    def save(self) -> None:
        """Persiste el mapa en `self.map_path` con permisos 600. Escribe
        primero a un fichero temporal y luego renombra atomicamente para
        que un fallo a mitad de escritura no corrompa el mapa anterior."""
        if self.map_path is None:
            return
        self.map_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "next_id": self._next_id,
            # ordenamos por valor de alias para que el fichero sea
            # estable entre runs y facil de revisar en diff.
            "forward": dict(sorted(self.forward.items(),
                                   key=lambda kv: kv[1])),
        }
        tmp = self.map_path.with_suffix(self.map_path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2,
                                  ensure_ascii=False) + "\n",
                       encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            # Filesystem que no soporte chmod (p.ej. FAT en USB): seguimos.
            # El usuario es responsable de la confidencialidad del mapa.
            pass
        tmp.replace(self.map_path)
        try:
            os.chmod(self.map_path, 0o600)
        except OSError:
            pass

    def load(self) -> None:
        """Carga el mapa desde `self.map_path`. Si esta corrupto, lanza
        ValueError en vez de empezar de cero silenciosamente (perder el
        mapa significa perder la trazabilidad de los aliases existentes
        en parquets ya generados)."""
        if not self.map_path or not self.map_path.exists():
            return
        try:
            payload = json.loads(self.map_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Mapa de anonimizacion corrupto: {self.map_path} ({e}). "
                "Mover a un nombre con backup y regenerar a partir de los "
                "parquets si es necesario."
            ) from e
        self.forward = {str(k): str(v)
                        for k, v in (payload.get("forward") or {}).items()}
        self.reverse_map = {v: k for k, v in self.forward.items()}
        # next_id: el maximo +1 si no esta declarado, para evitar
        # colisiones tras una edicion manual del mapa.
        declared = int(payload.get("next_id", 0))
        derived = (max((int(re.findall(r"\d+", a)[0])
                        for a in self.forward.values()), default=0) + 1)
        self._next_id = max(declared, derived, len(self.forward) + 1)

    def stats(self) -> dict:
        return {
            "n_usuarios": len(self.forward),
            "next_id": self._next_id,
            "path": str(self.map_path) if self.map_path else None,
        }

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------
    def _strip_prefix(self, v: str) -> tuple[str, bool]:
        if v.startswith("user:"):
            return v[5:], True
        return v, False

    def _format_alias(self, num: int) -> str:
        return f"{self.ALIAS_PREFIX}{num:0{self.ALIAS_PAD}d}{self.ALIAS_SUFFIX}"


# ----------------------------------------------------------------------
# Helpers de modulo
# ----------------------------------------------------------------------
def maybe_load(path: str | Path = DEFAULT_MAP_PATH) -> Optional[UserAnonymizer]:
    """Carga el mapa si existe; devuelve None si no. Util para scripts
    de evaluacion (verify_scenarios, comparar_clustering, barrido_tau)
    que solo necesitan el mapa para resolver el ground truth y NO deben
    crearlo (crearlo aqui significaria que el run del pipeline aun no
    se ha ejecutado y los aliases serian inconsistentes)."""
    p = Path(path)
    if not p.exists():
        return None
    return UserAnonymizer(p)


def make_anonymizer(enabled: bool,
                    map_path: str | Path = DEFAULT_MAP_PATH
                    ) -> Optional[UserAnonymizer]:
    """Factoria para los scripts del pipeline: si `enabled=False`
    devuelve None y el caller no debe aplicar anonimizacion; si
    `enabled=True` devuelve un `UserAnonymizer` con el mapa cargado."""
    return UserAnonymizer(map_path) if enabled else None


# ----------------------------------------------------------------------
# Tests rapidos
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile
    print("Tests de UserAnonymizer:")
    with tempfile.TemporaryDirectory() as d:
        mp = Path(d) / "map.json"
        a = UserAnonymizer(mp)

        # idempotencia
        x = a.anonymize("user:lab.user1")
        assert x == "user:user_0001_anonymized", x
        assert a.anonymize("user:lab.user1") == x

        # otro usuario incrementa contador
        y = a.anonymize("user:asmith")
        assert y == "user:user_0002_anonymized", y

        # sin prefijo
        z = a.anonymize("admin1")
        assert z == "user_0003_anonymized", z

        # mismo canonico aunque venga con/sin prefijo: NO -- por diseno,
        # los identificadores con prefijo son distintos a los sin prefijo
        # solo si el contenido canonico difiere. 'admin1' (sin prefijo)
        # se trata como un canonico distinto a 'user:admin1' si el caller
        # no lo normaliza. Aqui validamos que el lookup por canonico
        # tras strip funciona:
        w = a.anonymize("user:admin1")
        # 'admin1' ya estaba registrado con id 3; ahora reaparece con
        # prefijo y debe devolver el mismo alias con prefijo.
        assert w == "user:user_0003_anonymized", w

        # anonymize_set sobre set
        s = a.anonymize_set({"user:lab.user1", "user:bob"})
        assert s == {"user:user_0001_anonymized", "user:user_0004_anonymized"}, s

        # anonymize_set sobre lista (preserva orden)
        lst = a.anonymize_set(["user:lab.user1", "user:carol", "user:lab.user1"])
        assert lst == ["user:user_0001_anonymized",
                       "user:user_0005_anonymized",
                       "user:user_0001_anonymized"], lst

        # No re-anonimiza un alias
        already = a.anonymize("user:user_0001_anonymized")
        assert already == "user:user_0001_anonymized", already

        # anonymize_raw_user con valores crudos
        # registramos tfm.s06.victim1 primero
        a.anonymize("user:tfm.s06.victim1")
        raw = a.anonymize_raw_user("tfm.s06.victim1@labcorp.local")
        assert raw.startswith("user_"), raw
        assert raw.endswith("_anonymized"), raw
        # mismo alias para el mismo canonico, con o sin dominio
        raw2 = a.anonymize_raw_user("LABCORP\\tfm.s06.victim1")
        assert raw == raw2, f"{raw} != {raw2}"
        # valor vacio / no-string: se devuelve intacto sin pasar por normalizer
        assert a.anonymize_raw_user("") == ""
        assert a.anonymize_raw_user(None) is None
        # un usuario crudo nuevo que pase el normalizer se registra al vuelo
        nuevo = a.anonymize_raw_user("CORP\\nuevo.usuario@labcorp.local")
        assert nuevo.startswith("user_") and nuevo.endswith("_anonymized"), nuevo

        # lookup / lookup_raw NO auto-registran
        n_before = len(a.forward)
        miss = a.lookup("user:fulanito")
        assert miss is None, miss
        miss_raw = a.lookup_raw("FULANO@labcorp.local")
        assert miss_raw is None, miss_raw
        assert len(a.forward) == n_before, "lookup/lookup_raw NO deben auto-registrar"
        # lookup en una entrada existente
        hit = a.lookup("user:lab.user1")
        assert hit == "user:user_0001_anonymized", hit
        hit_raw = a.lookup_raw("LABCORP\\lab.user1")
        assert hit_raw == "user_0001_anonymized", hit_raw

        # anonymize_text
        text = ("User tfm.s06.victim1 logged in from 10.0.0.1. "
                "Then LABCORP\\tfm.s06.victim1 was used by lab.user1@labcorp.local.")
        out = a.anonymize_text(text)
        assert "tfm.s06.victim1" not in out, out
        assert "lab.user1" not in out, out
        assert "10.0.0.1" in out, "Las IPs NO se anonimizan"
        # el alias de victim1 debe aparecer al menos 2 veces
        ali = a.forward["tfm.s06.victim1"]
        assert out.count(ali) >= 2, out

        # reversa
        assert a.reverse("user:user_0001_anonymized") == "user:lab.user1"
        assert a.reverse("user_0001_anonymized") == "lab.user1"
        # alias desconocido: se devuelve tal cual
        assert a.reverse("user:user_9999_anonymized") == "user:user_9999_anonymized"

        # persistencia
        a.save()
        assert mp.exists()
        # permisos 600 (ignoramos en filesystems que no lo soporten)
        try:
            mode = oct(mp.stat().st_mode)[-3:]
            assert mode == "600", f"permisos esperados 600, son {mode}"
        except AssertionError as e:
            print(f"  AVISO: {e}")

        # reload preserva los aliases
        b = UserAnonymizer(mp)
        assert b.anonymize("user:lab.user1") == "user:user_0001_anonymized"
        # un nuevo usuario tras reload obtiene el siguiente id libre
        new = b.anonymize("user:zoe")
        assert new.endswith("_anonymized")
        assert new != "user:user_0001_anonymized"
        # known_users
        ku = b.known_users()
        assert "lab.user1" in ku and "tfm.s06.victim1" in ku, ku

        # maybe_load: si no existe devuelve None
        empty = maybe_load(Path(d) / "no-existe.json")
        assert empty is None

        # make_anonymizer
        none_anon = make_anonymizer(False, mp)
        assert none_anon is None
        on = make_anonymizer(True, mp)
        assert isinstance(on, UserAnonymizer)

    print("  TODOS OK")
