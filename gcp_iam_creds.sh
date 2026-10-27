#!/bin/bash
# ABOUTME: Ejecuta operaciones de credenciales IAM delegadas en GCP (signJwt,
# ABOUTME: signBlob, generateAccessToken, generateIdToken) sobre una o varias cuentas.

################################################################################
# Script de Gestión de Credenciales IAM en Google Cloud Platform
#
# Descripción:
#   Automatiza operaciones de credenciales delegadas en GCP usando la API
#   IAM Credentials. Permite firmar JWTs, firmar blobs, generar access tokens
#   e ID tokens para cuentas de servicio con delegación de permisos.
#
# Requisitos:
#   - curl y jq instalados
#   - Token de acceso OAuth 2.0 válido con permisos suficientes
#   - Delegante configurado con permisos "Service Account Token Creator"
#
# Uso:
#   $0 [-token <archivo> | -token-command <comando>] -delegate <cuenta_delegante>
#      [-file <lista_sa>] [-account <cuenta> ...] [cuenta ...]
#
#   Las cuentas destino se pueden indicar sin archivo: como argumentos
#   posicionales, con -account (repetible) o por entrada estándar (stdin).
#   El token tampoco requiere archivo: usa -token-command para obtenerlo.
#
# Ejemplo:
#   $0 -token-command "gcloud auth print-access-token" \
#      -delegate delegator@proyecto.iam.gserviceaccount.com \
#      destino@proyecto.iam.gserviceaccount.com
#   $0 -token token.txt -delegate delegator@proyecto.iam.gserviceaccount.com -file cuentas_servicio.txt
#
################################################################################

set -o pipefail

# ============================================================================
# CONFIGURACIÓN DE COLORES Y ESTILOS
# ============================================================================

GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
BOLD=$(tput bold)
RESET=$(tput sgr0)

# ============================================================================
# VARIABLES POR DEFECTO
# ============================================================================

SCOPES="https://www.googleapis.com/auth/cloud-platform"
AUDIENCE="https://example.com"
MENSAJE_FIRMA="deadbeef"
TIMEOUT=10
REINTENTOS=3

# Counters para estadísticas
TOTAL_PROCESADAS=0
EXITOSAS=0
FALLIDAS=0

# Fuentes de configuración (vacías hasta parsear argumentos)
TOKEN_FILE=""
TOKEN_COMMAND=""
ARCHIVO_CUENTAS=""
CUENTAS_INLINE=()

# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================

# Muestra el mensaje de ayuda
mostrar_ayuda() {
  cat << EOF
${BOLD}Uso:${RESET} $0 [-token <archivo> | -token-command <cmd>] -delegate <cuenta> [cuenta ...] [opciones]

${BOLD}Token de acceso (elige uno):${RESET}
  -token <archivo>        Archivo con el token de acceso OAuth 2.0
  -token-command <cmd>    Comando para obtener el token (ej: gcloud auth print-access-token)

${BOLD}Requerido:${RESET}
  -delegate <cuenta>      Email de la cuenta delegante (SA o usuario)

${BOLD}Cuentas destino (indica al menos una por cualquier vía):${RESET}
  <cuenta> ...            Una o más cuentas como argumentos posicionales
  -account <cuenta>       Cuenta destino (repetible)
  -file <lista>           Archivo con lista de cuentas destino (una por línea)
  (stdin)                 Si no se indica ninguna de las anteriores, se leen de la entrada estándar

${BOLD}Opciones:${RESET}
  -audience <url>         Audiencia para ID tokens (default: https://example.com)
  -message <hex>          Mensaje en hex para firmar (default: deadbeef)
  -timeout <seg>          Timeout para peticiones HTTP (default: 10)
  -help                   Muestra esta ayuda

${BOLD}Ejemplos:${RESET}
  $0 -token-command "gcloud auth print-access-token" -delegate del@proyecto.iam.gserviceaccount.com destino@proyecto.iam.gserviceaccount.com
  $0 -token token.txt -delegate del@proyecto.iam.gserviceaccount.com -account sa1@p.iam.gserviceaccount.com -account sa2@p.iam.gserviceaccount.com
  printf 'sa1@p.iam.gserviceaccount.com\nsa2@p.iam.gserviceaccount.com\n' | $0 -token-command "gcloud auth print-access-token" -delegate del@proyecto.iam.gserviceaccount.com
  $0 -token token.txt -delegate del@proyecto.iam.gserviceaccount.com -file cuentas.txt

EOF
  exit 0
}

# Registra un mensaje de error
registrar_error() {
  local cuenta="$1"
  local operacion="$2"
  local mensaje="$3"
  echo -e "${RED}❌ [$cuenta] $operacion: $mensaje${RESET}" >&2
}

# Registra un mensaje de éxito
registrar_exito() {
  local cuenta="$1"
  local operacion="$2"
  echo -e "${GREEN}✅ [$cuenta] $operacion${RESET}"
}

# Registra un mensaje informativo
registrar_info() {
  local mensaje="$1"
  echo -e "${CYAN}ℹ️  $mensaje${RESET}"
}

# Valida que un token sea válido JSON
validar_respuesta_json() {
  local respuesta="$1"
  if ! echo "$respuesta" | jq empty 2>/dev/null; then
    echo "false"
    return 1
  fi
  echo "true"
  return 0
}

# Valida que el archivo de token exista y sea legible
validar_token() {
  if [[ ! -f "$TOKEN_FILE" ]]; then
    echo "${RED}❌ Archivo de token no encontrado: $TOKEN_FILE${RESET}"
    exit 1
  fi

  if [[ ! -r "$TOKEN_FILE" ]]; then
    echo "${RED}❌ No hay permisos para leer: $TOKEN_FILE${RESET}"
    exit 1
  fi

  local token=$(cat "$TOKEN_FILE")
  if [[ -z "$token" ]]; then
    echo "${RED}❌ El archivo de token está vacío${RESET}"
    exit 1
  fi
}

# Valida que el archivo de cuentas exista y sea legible
validar_archivo_cuentas() {
  if [[ ! -f "$ARCHIVO_CUENTAS" ]]; then
    echo "${RED}❌ Archivo de cuentas no encontrado: $ARCHIVO_CUENTAS${RESET}"
    exit 1
  fi

  if [[ ! -r "$ARCHIVO_CUENTAS" ]]; then
    echo "${RED}❌ No hay permisos para leer: $ARCHIVO_CUENTAS${RESET}"
    exit 1
  fi

  local lineas=$(wc -l < "$ARCHIVO_CUENTAS")
  if [[ $lineas -eq 0 ]]; then
    echo "${RED}❌ El archivo de cuentas está vacío${RESET}"
    exit 1
  fi
}

# Resuelve el token de acceso desde un archivo o ejecutando un comando.
# Deja el valor en la variable global TOKEN_ACCESO.
resolver_token() {
  if [[ -n "$TOKEN_FILE" ]]; then
    validar_token
    TOKEN_ACCESO=$(cat "$TOKEN_FILE")
  else
    TOKEN_ACCESO=$(bash -c "$TOKEN_COMMAND")
    if [[ $? -ne 0 || -z "$TOKEN_ACCESO" ]]; then
      echo "${RED}❌ El comando de token no devolvió un token válido: $TOKEN_COMMAND${RESET}"
      exit 1
    fi
  fi
}

# ============================================================================
# OPERACIONES CON LA API IAM CREDENTIALS
# ============================================================================

# Firma un JWT usando la API signJwt
firmar_jwt() {
  local cuenta_destino="$1"

  local iat=$(date +%s)
  local exp=$((iat + 3600))

  registrar_info "Firmando JWT para $cuenta_destino..."

  # Construye el payload del JWT
  local claims=$(jq -cn \
    --arg iss "$cuenta_destino" \
    --arg scope "$SCOPES" \
    --arg aud "https://oauth2.googleapis.com/token" \
    --argjson iat "$iat" \
    --argjson exp "$exp" \
    '{iss:$iss,scope:$scope,aud:$aud,iat:$iat,exp:$exp}')

  local peticion=$(jq -cn \
    --arg del "$DELEGANTE" \
    --arg payload "$claims" \
    '{delegates:[$del],payload:$payload}')

  local respuesta=$(curl -s \
    --max-time "$TIMEOUT" \
    -H "Authorization: Bearer $TOKEN_ACCESO" \
    -H "Content-Type: application/json" \
    -X POST \
    --data "$peticion" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$cuenta_destino:signJwt")

  # Verifica la respuesta
  if echo "$respuesta" | jq -e '.signedJwt' > /dev/null 2>&1; then
    registrar_exito "$cuenta_destino" "Firma JWT"
    echo "$respuesta" | jq -r '.signedJwt'
    return 0
  else
    local mensaje=$(echo "$respuesta" | jq -r '.error.message // "Error desconocido"')
    registrar_error "$cuenta_destino" "Firma JWT" "$mensaje"
    return 1
  fi
}

# Firma un blob de datos usando la API signBlob
firmar_blob() {
  local cuenta_destino="$1"

  registrar_info "Firmando blob para $cuenta_destino..."

  local peticion=$(jq -cn \
    --arg del "$DELEGANTE" \
    --arg payload "$MENSAJE_FIRMA" \
    '{delegates:[$del],payload:$payload}')

  local respuesta=$(curl -s \
    --max-time "$TIMEOUT" \
    -H "Authorization: Bearer $TOKEN_ACCESO" \
    -H "Content-Type: application/json" \
    -X POST \
    --data "$peticion" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$cuenta_destino:signBlob")

  if echo "$respuesta" | jq -e '.signedBlob' > /dev/null 2>&1; then
    registrar_exito "$cuenta_destino" "Firma Blob"
    echo "$respuesta" | jq -r '.signedBlob'
    return 0
  else
    local mensaje=$(echo "$respuesta" | jq -r '.error.message // "Error desconocido"')
    registrar_error "$cuenta_destino" "Firma Blob" "$mensaje"
    return 1
  fi
}

# Genera un access token usando la API generateAccessToken
generar_access_token() {
  local cuenta_destino="$1"

  registrar_info "Generando access token para $cuenta_destino..."

  local peticion=$(jq -cn \
    --arg del "$DELEGANTE" \
    --argjson scopes "[\"$SCOPES\"]" \
    '{delegates:[$del],scope:$scopes}')

  local respuesta=$(curl -s \
    --max-time "$TIMEOUT" \
    -H "Authorization: Bearer $TOKEN_ACCESO" \
    -H "Content-Type: application/json" \
    -X POST \
    --data "$peticion" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$cuenta_destino:generateAccessToken")

  if echo "$respuesta" | jq -e '.accessToken' > /dev/null 2>&1; then
    registrar_exito "$cuenta_destino" "Access Token"
    echo "$respuesta" | jq
    return 0
  else
    local mensaje=$(echo "$respuesta" | jq -r '.error.message // "Error desconocido"')
    registrar_error "$cuenta_destino" "Access Token" "$mensaje"
    return 1
  fi
}

# Genera un ID token usando la API generateIdToken
generar_id_token() {
  local cuenta_destino="$1"

  registrar_info "Generando ID token para $cuenta_destino..."

  local peticion=$(jq -cn \
    --arg del "$DELEGANTE" \
    --arg aud "$AUDIENCE" \
    '{delegates:[$del],audience:$aud,includeEmail:true}')

  local respuesta=$(curl -s \
    --max-time "$TIMEOUT" \
    -H "Authorization: Bearer $TOKEN_ACCESO" \
    -H "Content-Type: application/json" \
    -X POST \
    --data "$peticion" \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$cuenta_destino:generateIdToken")

  if echo "$respuesta" | jq -e '.token' > /dev/null 2>&1; then
    registrar_exito "$cuenta_destino" "ID Token"
    echo "$respuesta" | jq
    return 0
  else
    local mensaje=$(echo "$respuesta" | jq -r '.error.message // "Error desconocido"')
    registrar_error "$cuenta_destino" "ID Token" "$mensaje"
    return 1
  fi
}

# ============================================================================
# PROCESAMIENTO PRINCIPAL
# ============================================================================

# Procesa una cuenta de servicio ejecutando todas las operaciones
procesar_cuenta() {
  local cuenta="$1"

  # Salta líneas vacías y comentarios
  cuenta=$(echo "$cuenta" | xargs)
  if [[ -z "$cuenta" ]] || [[ "$cuenta" =~ ^# ]]; then
    return
  fi

  ((TOTAL_PROCESADAS++))

  echo ""
  echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}Cuenta de servicio: $cuenta${RESET}"
  echo -e "${CYAN}════════════════════════════════════════════════════════════════${RESET}"

  # Ejecuta todas las operaciones
  local operaciones_exitosas=0

  firmar_jwt "$cuenta" && ((operaciones_exitosas++))
  echo ""

  firmar_blob "$cuenta" && ((operaciones_exitosas++))
  echo ""

  generar_access_token "$cuenta" && ((operaciones_exitosas++))
  echo ""

  generar_id_token "$cuenta" && ((operaciones_exitosas++))
  echo ""

  # Actualiza contadores
  if [[ $operaciones_exitosas -eq 4 ]]; then
    ((EXITOSAS++))
  else
    ((FALLIDAS++))
  fi
}

# Muestra resumen final
mostrar_resumen() {
  echo ""
  echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}RESUMEN DE EJECUCIÓN${RESET}"
  echo -e "${CYAN}════════════════════════════════════════════════════════════════${RESET}"
  echo "Total procesadas:    $TOTAL_PROCESADAS"
  echo -e "Completadas:         ${GREEN}$EXITOSAS${RESET}"
  echo -e "Con errores:         ${RED}$FALLIDAS${RESET}"
  echo -e "${CYAN}════════════════════════════════════════════════════════════════${RESET}"
  echo ""
}

# ============================================================================
# PARSEO DE ARGUMENTOS
# ============================================================================

while [[ $# -gt 0 ]]; do
  case "$1" in
    -token)
      TOKEN_FILE="$2"
      shift 2
      ;;
    -token-command)
      TOKEN_COMMAND="$2"
      shift 2
      ;;
    -account)
      CUENTAS_INLINE+=("$2")
      shift 2
      ;;
    -delegate)
      DELEGANTE="$2"
      shift 2
      ;;
    -file)
      ARCHIVO_CUENTAS="$2"
      shift 2
      ;;
    -audience)
      AUDIENCE="$2"
      shift 2
      ;;
    -message)
      MENSAJE_FIRMA="$2"
      shift 2
      ;;
    -timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    -help|-h)
      mostrar_ayuda
      ;;
    -*)
      echo "${RED}❌ Argumento desconocido: $1${RESET}"
      mostrar_ayuda
      ;;
    *)
      # Argumento posicional: se interpreta como cuenta de servicio destino
      CUENTAS_INLINE+=("$1")
      shift
      ;;
  esac
done

# ============================================================================
# VALIDACIONES INICIALES
# ============================================================================

# El delegante siempre es obligatorio
if [[ -z "$DELEGANTE" ]]; then
  echo "${RED}❌ Falta el argumento requerido -delegate.${RESET}"
  echo ""
  mostrar_ayuda
fi

# El token requiere exactamente una fuente: -token o -token-command
if [[ -n "$TOKEN_FILE" && -n "$TOKEN_COMMAND" ]]; then
  echo "${RED}❌ Usa solo una fuente de token: -token o -token-command, no ambas.${RESET}"
  echo ""
  mostrar_ayuda
fi
if [[ -z "$TOKEN_FILE" && -z "$TOKEN_COMMAND" ]]; then
  echo "${RED}❌ Falta el token de acceso: indica -token <archivo> o -token-command <cmd>.${RESET}"
  echo ""
  mostrar_ayuda
fi

# Las cuentas destino pueden venir de -file, -account/posicionales o stdin.
# Si no hay archivo ni cuentas en línea y la entrada estándar es una tubería,
# se leen las cuentas de stdin.
if [[ -z "$ARCHIVO_CUENTAS" && ${#CUENTAS_INLINE[@]} -eq 0 && ! -t 0 ]]; then
  while IFS= read -r _cuenta_stdin; do
    CUENTAS_INLINE+=("$_cuenta_stdin")
  done
fi

# Debe existir al menos una fuente de cuentas destino
if [[ -z "$ARCHIVO_CUENTAS" && ${#CUENTAS_INLINE[@]} -eq 0 ]]; then
  echo "${RED}❌ No se indicaron cuentas destino.${RESET}"
  echo "${YELLOW}   Usa argumentos posicionales, -account, -file o canaliza una lista por stdin.${RESET}"
  echo ""
  mostrar_ayuda
fi

# Valida el archivo de cuentas solo si se proporcionó uno
if [[ -n "$ARCHIVO_CUENTAS" ]]; then
  validar_archivo_cuentas
fi

# Resuelve el token (archivo o comando)
resolver_token

echo -e "${BOLD}${GREEN}✓ Configuración validada${RESET}"
echo -e "  Delegante:  $DELEGANTE"
if [[ -n "$ARCHIVO_CUENTAS" ]]; then
  echo -e "  Cuentas:    archivo $ARCHIVO_CUENTAS + ${#CUENTAS_INLINE[@]} en línea"
else
  echo -e "  Cuentas:    ${#CUENTAS_INLINE[@]} indicada(s) directamente"
fi
echo ""

# ============================================================================
# EJECUCIÓN PRINCIPAL
# ============================================================================

# Procesa las cuentas del archivo, si se indicó uno
if [[ -n "$ARCHIVO_CUENTAS" ]]; then
  while IFS= read -r cuenta; do
    procesar_cuenta "$cuenta"
  done < "$ARCHIVO_CUENTAS"
fi

# Procesa las cuentas indicadas en línea (-account, posicionales o stdin)
for cuenta in "${CUENTAS_INLINE[@]}"; do
  procesar_cuenta "$cuenta"
done

# Muestra el resumen
mostrar_resumen

exit 0
