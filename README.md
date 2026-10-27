# iam_gcp_creds

Gestión de credenciales IAM delegadas en Google Cloud Platform. Para cada cuenta
de servicio destino ejecuta `signJwt`, `signBlob`, `generateAccessToken` y
`generateIdToken` usando la API IAM Credentials.

## Requisitos

- `curl` y `jq` instalados.
- Token de acceso OAuth 2.0 válido con permisos suficientes.
- Delegante con el rol *Service Account Token Creator*.

## Uso

Ningún archivo `.txt` es obligatorio. El token y las cuentas destino se pueden
indicar sin crear archivos.

### Token de acceso (elige una fuente)

- `-token <archivo>` — lee el token de un archivo.
- `-token-command "<comando>"` — obtiene el token ejecutando un comando.

### Cuentas destino (indica al menos una por cualquier vía)

- Argumentos posicionales: `destino@proyecto.iam.gserviceaccount.com`
- `-account <cuenta>` (repetible)
- `-file <lista>` — archivo con una cuenta por línea
- Entrada estándar (stdin), si no se indica ninguna de las anteriores

## Ejemplos

Sin ningún archivo, obteniendo el token con `gcloud` y pasando la cuenta directamente:

```bash
./gcp_iam_creds.sh \
  -token-command "gcloud auth print-access-token" \
  -delegate delegator@proyecto.iam.gserviceaccount.com \
  destino@proyecto.iam.gserviceaccount.com
```

Varias cuentas con `-account`:

```bash
./gcp_iam_creds.sh \
  -token-command "gcloud auth print-access-token" \
  -delegate delegator@proyecto.iam.gserviceaccount.com \
  -account sa1@proyecto.iam.gserviceaccount.com \
  -account sa2@proyecto.iam.gserviceaccount.com
```

Cuentas por stdin:

```bash
printf 'sa1@proyecto.iam.gserviceaccount.com\nsa2@proyecto.iam.gserviceaccount.com\n' \
  | ./gcp_iam_creds.sh -token-command "gcloud auth print-access-token" \
      -delegate delegator@proyecto.iam.gserviceaccount.com
```

Modo con archivos (sigue soportado):

```bash
./gcp_iam_creds.sh -token token.txt \
  -delegate delegator@proyecto.iam.gserviceaccount.com \
  -file cuentas_servicio.txt
```

Ayuda completa:

```bash
./gcp_iam_creds.sh -help
```

## Pruebas

```bash
./test_gcp_iam_creds.sh
```

Las pruebas sustituyen `curl` por un stub, así que no realizan llamadas reales a
la API de GCP.
