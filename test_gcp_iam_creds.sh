#!/bin/bash
# ABOUTME: Pruebas del parseo de argumentos y fuentes de cuentas de gcp_iam_creds.sh.
# ABOUTME: Sustituye curl por un stub para no realizar llamadas reales a la API de GCP.

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$SCRIPT_DIR/gcp_iam_creds.sh"

PRUEBAS=0
FALLOS=0

# Directorio temporal con un curl falso que siempre responde un error JSON,
# de modo que las operaciones "fallan" de forma controlada sin red.
STUB_DIR=$(mktemp -d)
trap 'rm -rf "$STUB_DIR"' EXIT
cat > "$STUB_DIR/curl" << 'EOF'
#!/bin/bash
echo '{"error":{"message":"stub: sin red"}}'
EOF
chmod +x "$STUB_DIR/curl"

# Ejecuta el script con el curl falso al frente del PATH y SIN datos en stdin
# (stdin tomado de /dev/null: tubería vacía, no interactiva).
# Uso: correr <args...>
correr() {
  PATH="$STUB_DIR:$PATH" bash "$SCRIPT" "$@" < /dev/null 2>&1
}

# Igual que correr, pero canaliza <entrada> por stdin.
# Uso: correr_stdin <entrada> <args...>
correr_stdin() {
  local entrada="$1"; shift
  PATH="$STUB_DIR:$PATH" bash "$SCRIPT" "$@" <<< "$entrada" 2>&1
}

afirmar_contiene() {
  local nombre="$1" salida="$2" aguja="$3"
  ((PRUEBAS++))
  if grep -qF -- "$aguja" <<< "$salida"; then
    echo "  PASS: $nombre"
  else
    echo "  FAIL: $nombre"
    echo "    esperaba encontrar: $aguja"
    echo "    salida real:"
    sed 's/^/      /' <<< "$salida"
    ((FALLOS++))
  fi
}

afirmar_no_contiene() {
  local nombre="$1" salida="$2" aguja="$3"
  ((PRUEBAS++))
  if grep -qF -- "$aguja" <<< "$salida"; then
    echo "  FAIL: $nombre"
    echo "    no esperaba encontrar: $aguja"
    ((FALLOS++))
  else
    echo "  PASS: $nombre"
  fi
}

echo "== Sintaxis =="
if bash -n "$SCRIPT"; then echo "  PASS: bash -n"; ((PRUEBAS++)); else echo "  FAIL: bash -n"; ((PRUEBAS++)); ((FALLOS++)); fi

echo "== Ayuda =="
OUT=$(correr -help)
afirmar_contiene "ayuda menciona -account" "$OUT" "-account"
afirmar_contiene "ayuda menciona -token-command" "$OUT" "-token-command"
afirmar_contiene "ayuda menciona stdin" "$OUT" "stdin"

echo "== Validaciones =="
OUT=$(correr -token-command "echo t")
afirmar_contiene "falta delegate" "$OUT" "-delegate"

OUT=$(correr -delegate del@x.iam.gserviceaccount.com sa@x.iam.gserviceaccount.com)
afirmar_contiene "falta token" "$OUT" "Falta el token de acceso"

TOKEN_TMP=$(mktemp); echo "tok" > "$TOKEN_TMP"
OUT=$(correr -token "$TOKEN_TMP" -token-command "echo t" -delegate del@x sa@x)
afirmar_contiene "dos fuentes de token" "$OUT" "una fuente de token"
rm -f "$TOKEN_TMP"

OUT=$(correr -token-command "echo t" -delegate del@x.iam.gserviceaccount.com)
afirmar_contiene "sin cuentas destino" "$OUT" "No se indicaron cuentas destino"

echo "== Cuenta posicional (sin archivo) =="
OUT=$(correr -token-command "echo faketoken" -delegate del@x.iam.gserviceaccount.com destino@x.iam.gserviceaccount.com)
afirmar_contiene "procesa la cuenta posicional" "$OUT" "Cuenta de servicio: destino@x.iam.gserviceaccount.com"
afirmar_contiene "muestra resumen" "$OUT" "RESUMEN DE EJECUCIÓN"
afirmar_no_contiene "no exige archivo" "$OUT" "Archivo de cuentas no encontrado"
afirmar_no_contiene "no exige cuentas" "$OUT" "No se indicaron cuentas destino"

echo "== Cuenta con -account (sin archivo) =="
OUT=$(correr -token-command "echo faketoken" -delegate del@x -account sa1@x.iam.gserviceaccount.com -account sa2@x.iam.gserviceaccount.com)
afirmar_contiene "procesa sa1" "$OUT" "Cuenta de servicio: sa1@x.iam.gserviceaccount.com"
afirmar_contiene "procesa sa2" "$OUT" "Cuenta de servicio: sa2@x.iam.gserviceaccount.com"

echo "== Cuentas por stdin (sin archivo) =="
OUT=$(correr_stdin $'sa-stdin@x.iam.gserviceaccount.com\n' -token-command "echo faketoken" -delegate del@x)
afirmar_contiene "procesa cuenta de stdin" "$OUT" "Cuenta de servicio: sa-stdin@x.iam.gserviceaccount.com"

echo "== Compatibilidad: -token archivo + -file =="
TOKEN_TMP=$(mktemp); echo "tok" > "$TOKEN_TMP"
LISTA_TMP=$(mktemp); printf 'sa-file@x.iam.gserviceaccount.com\n' > "$LISTA_TMP"
OUT=$(correr -token "$TOKEN_TMP" -delegate del@x -file "$LISTA_TMP")
afirmar_contiene "procesa cuenta de archivo" "$OUT" "Cuenta de servicio: sa-file@x.iam.gserviceaccount.com"
rm -f "$TOKEN_TMP" "$LISTA_TMP"

echo ""
echo "== Resultado: $((PRUEBAS - FALLOS))/$PRUEBAS pruebas superadas =="
if [[ $FALLOS -gt 0 ]]; then
  exit 1
fi
exit 0
