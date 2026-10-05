#!/bin/bash

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
#   $0 [-token <archivo> | -token-command <comando>] -delegate <cuenta_delegante> -file <lista_sa>
#
# Ejemplo:
#   $0 -token token.txt -delegate delegator@proyecto.iam.gserviceaccount.com -file cuentas_servicio.txt
#   $0 -token-command "gcloud auth print-access-token" -delegate delegator@proyecto.iam.gserviceaccount.com -file cuentas.txt
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

# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================

# Muestra el mensaje de ayuda
mostrar_ayuda() {
  cat << EOF
${BOLD}Uso:${RESET} $0 [-token <archivo> | -token-command <comando>] -delegate <cuenta> -file <lista> [opciones]

${BOLD}Argumentos requeridos (elige uno):${RESET}
  -token <archivo>        Archivo con el token de acceso OAuth 2.0
  -token-command <cmd>    Comando para obtener el token (ej: gcloud auth print-access-token)
  -delegate <cuenta>      Email de la cuenta delegante (SA o usuario)
  -file <lista>           Archivo con lista de cuentas destino (una por línea)

${BOLD}Opciones:${RESET}
  -audience <url>         Audiencia para ID tokens (default: https://example.com)
  -message <hex>          Mensaje en hex para firmar (default: deadbeef)
  -timeout <seg>          Timeout para peticiones HTTP (default: 10)
  -help                   Muestra esta ayuda

${BOLD}Ejemplos:${RESET}
  $0 -token token.txt -delegate delegator@proyecto.iam.gserviceaccount.com -file cuentas.txt
  $0 -token-command "gcloud auth print-access-token" -delegate delegator@proyecto.iam.gserviceaccount.com -file cuentas.txt

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
    *)
      echo "${RED}❌ Argumento desconocido: $1${RESET}"
      mostrar_ayuda
      ;;
  esac
done

# ============================================================================
# VALIDACIONES INICIALES
# ============================================================================

if [[ -z "$TOKEN_FILE" || -z "$DELEGANTE" || -z "$ARCHIVO_CUENTAS" ]]; then
  echo "${RED}❌ Faltan argumentos requeridos.${RESET}"
  echo ""
  mostrar_ayuda
fi

# Valida los archivos y token
validar_token
validar_archivo_cuentas

# Lee el token
TOKEN_ACCESO=$(cat "$TOKEN_FILE")

echo -e "${BOLD}${GREEN}✓ Configuración validada${RESET}"
echo -e "  Delegante:  $DELEGANTE"
echo -e "  Cuentas:    $ARCHIVO_CUENTAS"
echo ""

# ============================================================================
# EJECUCIÓN PRINCIPAL
# ============================================================================

while IFS= read -r cuenta; do
  procesar_cuenta "$cuenta"
done < "$ARCHIVO_CUENTAS"

# Muestra el resumen
mostrar_resumen

exit 0

On Sun, Oct 4, 2026 at 5:30 PM aaron.chock <aaron.chock@gmail.com> wrote:
#!/bin/bash

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
#   $0 -token <archivo_token> -delegate <cuenta_delegante> -file <lista_sa>
#
# Ejemplo:
#   $0 -token token.txt -delegate delegator@proyecto.iam.gserviceaccount.com \
#      -file cuentas_servicio.txt
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

# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================

# Muestra el mensaje de ayuda
mostrar_ayuda() {
  cat << EOF
${BOLD}Uso:${RESET} $0 -token <archivo> -delegate <cuenta> -file <lista> [opciones]

${BOLD}Argumentos requeridos:${RESET}
  -token <archivo>        Archivo con el token de acceso OAuth 2.0
  -delegate <cuenta>      Email de la cuenta delegante (SA o usuario)
  -file <lista>           Archivo con lista de cuentas destino (una por línea)

${BOLD}Opciones:${RESET}
  -audience <url>         Audiencia para ID tokens (default: https://example.com)
  -message <hex>          Mensaje en hex para firmar (default: deadbeef)
  -timeout <seg>          Timeout para peticiones HTTP (default: 10)
  -help                   Muestra esta ayuda

${BOLD}Ejemplos:${RESET}
  $0 -token token.txt -delegate delegator@proyecto.iam.gserviceaccount.com -file cuentas.txt
  $0 -token token.txt -delegate delegator@proyecto.iam.gserviceaccount.com -file cuentas.txt -timeout 20

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
    *)
      echo "${RED}❌ Argumento desconocido: $1${RESET}"
      mostrar_ayuda
      ;;
  esac
done

# ============================================================================
# VALIDACIONES INICIALES
# ============================================================================

if [[ -z "$TOKEN_FILE" || -z "$DELEGANTE" || -z "$ARCHIVO_CUENTAS" ]]; then
  echo "${RED}❌ Faltan argumentos requeridos.${RESET}"
  echo ""
  mostrar_ayuda
fi

# Valida los archivos y token
validar_token
validar_archivo_cuentas

# Lee el token
TOKEN_ACCESO=$(cat "$TOKEN_FILE")

echo -e "${BOLD}${GREEN}✓ Configuración validada${RESET}"
echo -e "  Delegante:  $DELEGANTE"
echo -e "  Cuentas:    $ARCHIVO_CUENTAS"
echo ""

# ============================================================================
# EJECUCIÓN PRINCIPAL
# ============================================================================

while IFS= read -r cuenta; do
  procesar_cuenta "$cuenta"
done < "$ARCHIVO_CUENTAS"

# Muestra el resumen
mostrar_resumen

exit 0
