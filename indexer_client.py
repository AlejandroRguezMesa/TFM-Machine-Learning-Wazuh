"""
indexer_client.py — Cliente OpenSearch para el Wazuh Indexer.

Maneja:
  - Conexión vía túnel SSH (default) o directa
  - Auth básica con usuario read-only
  - SSL self-signed (común en Wazuh all-in-one)
  - Configuración desde variables de entorno o argumentos

Variables de entorno (recomendado para no hardcodear credenciales):
  WAZUH_INDEXER_HOST  default: localhost
  WAZUH_INDEXER_PORT  default: 9200
  WAZUH_INDEXER_USER  default: tfm_analyst
  WAZUH_INDEXER_PASS  (sin default, obligatoria)

Para crear el .env:
  cat > .env <<EOF
  WAZUH_INDEXER_HOST=localhost
  WAZUH_INDEXER_PORT=9200
  WAZUH_INDEXER_USER=tfm_analyst
  WAZUH_INDEXER_PASS=tu_password_aqui
  EOF
  chmod 600 .env

Uso desde scripts:
    from indexer_client import get_client
    client = get_client()
    print(client.info())
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

try:
    from opensearchpy import OpenSearch, RequestsHttpConnection
    from opensearchpy.exceptions import (
        AuthenticationException, AuthorizationException,
        ConnectionError as OSConnectionError,
    )
except ImportError:
    raise SystemExit(
        "Falta opensearch-py. Instala con:\n"
        "    pip install opensearch-py python-dotenv"
    )

# Silencio especifico del warning de cert self-signed que urllib3 emite
# en cada peticion al Indexer: desactivamos solo la categoria concreta
# (no un filtro global de warnings, que afectaria a todos los modulos
# que importen este).
try:
    from urllib3 import disable_warnings
    from urllib3.exceptions import InsecureRequestWarning
    _CAN_DISABLE_URLLIB3 = True
except ImportError:
    _CAN_DISABLE_URLLIB3 = False


def _load_env():
    """Carga .env del directorio del script si existe."""
    try:
        from dotenv import load_dotenv
        env_path = Path(__file__).resolve().parent / ".env"
        if env_path.exists():
            load_dotenv(env_path)
    except ImportError:
        pass  # dotenv es opcional


def get_client(host=None, port=None, user=None, password=None,
               verify_certs=False, timeout=120):
    """Construye y devuelve un cliente OpenSearch listo para usar."""
    _load_env()

    host = host or os.environ.get("WAZUH_INDEXER_HOST", "localhost")
    port = int(port or os.environ.get("WAZUH_INDEXER_PORT", 9200))
    user = user or os.environ.get("WAZUH_INDEXER_USER", "tfm_analyst")
    password = password or os.environ.get("WAZUH_INDEXER_PASS")

    if not password:
        raise SystemExit(
            "Falta WAZUH_INDEXER_PASS.\n"
            "Define la variable de entorno o crea un fichero .env "
            "(ver docstring de indexer_client.py)."
        )

    # Wazuh suele usar certs self-signed; silencia la advertencia
    # concreta de urllib3, no todas las warnings.
    if not verify_certs and _CAN_DISABLE_URLLIB3:
        disable_warnings(InsecureRequestWarning)

    client = OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_auth=(user, password),
        use_ssl=True,
        verify_certs=verify_certs,
        ssl_show_warn=False,
        connection_class=RequestsHttpConnection,
        timeout=timeout,
        max_retries=3,
        retry_on_timeout=True,
    )

    return client


def test_connection(client=None):
    """Verifica que la conexión funciona y muestra info básica del cluster."""
    client = client or get_client()
    try:
        info = client.info()
        print(f"✓ Conectado a {info['cluster_name']}")
        print(f"  versión OpenSearch: {info['version']['number']}")

        # listar índices wazuh-alerts-*
        cat = client.cat.indices(index="wazuh-alerts-*", format="json")
        if cat:
            print(f"\n  Índices wazuh-alerts-* encontrados: {len(cat)}")
            for idx in sorted(cat, key=lambda x: x["index"])[-5:]:
                print(f"    {idx['index']:<40} docs.count={idx['docs.count']:>12}  "
                      f"store.size={idx['store.size']:>8}")
        else:
            print("\n  ⚠ No se encontraron índices wazuh-alerts-*")
        return True
    except AuthenticationException:
        print("✗ Credenciales incorrectas", file=sys.stderr)
        return False
    except AuthorizationException as e:
        print(f"✗ Sin permisos: {e}", file=sys.stderr)
        return False
    except OSConnectionError as e:
        print(f"✗ No se puede conectar a {client.transport.hosts}: {e}",
              file=sys.stderr)
        print("\n  Posibles causas:", file=sys.stderr)
        print("  - El indexer no está escuchando en ese puerto", file=sys.stderr)
        print("  - El túnel SSH no está activo "
              "(ssh -L 9200:127.0.0.1:9200 user@host)", file=sys.stderr)
        return False
    except Exception as e:
        print(f"✗ Error inesperado: {type(e).__name__}: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    # Test rápido de conexión
    print("Probando conexión al Wazuh Indexer...")
    ok = test_connection()
    sys.exit(0 if ok else 1)
