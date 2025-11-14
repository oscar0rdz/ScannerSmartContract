ScannerUsdt — Pipeline ligero para descubrir y auditar contratos ERC-20 activos

Este repositorio reúne un conjunto de scripts en Python para:

Escanear eventos Transfer de tokens ERC-20 (USDT, USDC, DAI, WETH).

Detectar qué contratos interactúan con esos tokens y con qué volumen.

Aplicar heurísticas de riesgo sobre el bytecode (delegatecall, selfdestruct, etc.).

Descargar fuente/ABI/metadata desde Etherscan v2.

Lanzar una auditoría rápida semi-automática sobre los contratos más interesantes, con integración opcional a Slither/Mythril.

El foco es tener un flujo reproducible y fácil de demostrar que muestre criterio de selección de contratos, automatización básica y mentalidad de seguridad aplicada a DeFi.

Demo

Espacio reservado para un GIF corto mostrando el flujo completo (scan → filtro → auditoría):

<p align="center">
  <img src="docs/demo.gif" alt="Demo ScannerUsdt"
       style="max-width: 900px; width: 100%; height: auto;">
</p>


Qué aporta este proyecto 

Este repositorio busca demostrar:

Capacidad para trabajar con datos on-chain: JSON-RPC, logs de eventos, bytecode.

Entendimiento de riesgos de seguridad en contratos inteligentes (delegatecall, selfdestruct, oráculos, loops sin acotar, etc.).

Organización de un pipeline de análisis en etapas:

Descubrimiento (scanner).

Priorización (filtro basado en volumen + risk flags).

Auditoría focalizada (descarga de source/ABI, heurísticas y herramientas estáticas).

No es “otro script suelto”: la idea es acercarse a cómo trabajaría un analista junior de seguridad DeFi que necesita decidir a qué contratos dedicar tiempo.

Estructura principal del repositorio

token_transfer_scanner.py
Escáner multi-token (USDT, USDC, DAI, WETH).

Usa ETH_RPC_URL para conectarse a un nodo Ethereum (mainnet).

Recupera eventos Transfer del token en un rango de bloques.

Agrupa por dirección (from/to), calcula:

número de interacciones,

volumen normalizado (volume_token),

primer y último bloque.

Llama a eth_getCode para esas direcciones y marca solo las que son contratos.

Extrae banderas de riesgo simples del bytecode:

uses_delegatecall_opcode

uses_callcode_opcode

can_selfdestruct_opcode

filter_and_audit_from_scanner.py
Fase de filtrado + orquestación de auditorías.

Carga el JSON generado por el scanner.

Aplica reglas de priorización:

volumen mínimo configurable (--min-volume, por defecto 1000 unidades de token),

requiere al menos las banderas uses_delegatecall_opcode y can_selfdestruct_opcode.

Consulta Etherscan v2 (getsourcecode) para comprobar que el contrato está verificado y obtener:

SourceCode,

ABI,

metadata básica (nombre de contrato, compilador, etc.).

Clasifica contratos como bluechip o no (Uniswap, Aave, Curve, etc. marcados, pero no descartados).

Guarda candidates_for_audit.json y lanza contract_deep_audit.py --no-mythril sobre cada address seleccionada.

contract_deep_audit.py
Auditoría rápida de un contrato concreto.

Descarga y guarda:

source.sol,

abi.json,

metadata.json,
usando Etherscan v2.

Usa ETH_RPC_URL para:

eth_getCode (bytecode on-chain),

eth_getBalance (balance en ETH).

Aplica una serie de heurísticas sobre fuente y bytecode, por ejemplo:

risk_flags:

uses_delegatecall_opcode

can_selfdestruct_opcode

uses_inline_assembly

uses_tx_origin (si aplica)

design_flags:

uso de block.timestamp,

dependencia de address(this).balance,

bucles for sobre arrays de longitud dinámica.

detección de posibles funciones críticas:

deposit, withdraw, claim, flashLoan, upgradeTo, transferOwnership, etc.

detección básica de patrones de oráculos (uso de latestRoundData, pricePerShare, exchangeRate, etc. si aparecen).

Integra, de forma opcional y controlada por .env, la ejecución de:

Slither (análisis estático sobre fuente verificada).

Mythril (ejecución simbólica sobre bytecode), con:

profundidad y timeout configurables para evitar bloqueos.

env_utils.py
Helper pequeño para gestionar variables de entorno del proyecto.

Carga el .env de la raíz de forma explícita (evitando problemas de load_dotenv() en REPL/heredoc).

Ofrece un pequeño CLI:

python -m env_utils print ETH_RPC_URL

python -m env_utils run "python contract_deep_audit.py --address 0x..."

requirements.txt
Dependencias principales:

web3

requests

python-dotenv

(opcional) Slither/Mythril instalados a nivel sistema.

audit_output/ (generado en runtime)
Carpeta con una subcarpeta por contrato auditado:

audit_output/<address>/source.sol

audit_output/<address>/abi.json

audit_output/<address>/metadata.json

audit_output/<address>/summary.json

audit_output/<address>/slither_report.json (si se ejecutó Slither)

audit_output/<address>/mythril_report.json (si se ejecutó Mythril)

Requisitos y configuración
Entorno

Python 3.10+ (desarrollado y probado con Python 3.12).

virtualenv recomendado.

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Variables de entorno (.env en la raíz del proyecto)
# Nodo RPC (mainnet)
ETH_RPC_URL="https://mainnet.infura.io/v3/tu_project_id"

# Clave de Etherscan (v2)
ETHERSCAN_API_KEY="tu_api_key"
ETHERSCAN_CHAIN_ID=1  # 1 = Ethereum mainnet

# Opcionales: integración con herramientas externas
SLITHER_CMD="slither"       # si el binario no está en el PATH por defecto
MYTHRIL_CMD="myth"          # idem
MYTHRIL_ENABLED=0           # 0 = no correr Mythril por defecto
MYTHRIL_DEPTH=8             # profundidad de análisis simbólico
MYTHRIL_TIMEOUT_SECS=120    # timeout duro en segundos para Mythril

Flujo de trabajo típico
1. Escanear un token (descubrimiento de contratos)

Ejemplo: escanear USDT en los últimos 3000 bloques y guardar resultados:

.venv/bin/python token_transfer_scanner.py \
    --token usdt \
    --blocks-back 3000 \
    --limit 200 \
    > scanner_usdt.json


Puedes repetir el mismo patrón con otros tokens:

# DAI
.venv/bin/python token_transfer_scanner.py --token dai --blocks-back 5000 --limit 300 > scanner_dai.json

# WETH
.venv/bin/python token_transfer_scanner.py --token weth --blocks-back 5000 --limit 300 > scanner_weth.json

2. Filtrar candidatos de alto riesgo

A partir del JSON del scanner:

.venv/bin/python filter_and_audit_from_scanner.py \
    scanner_usdt.json \
    --min-volume 1000 \
    --max 20


El filtro:

Exige volume_token >= min-volume.

Requiere que risk_flags contenga al menos:

uses_delegatecall_opcode

can_selfdestruct_opcode

Consulta Etherscan v2 para quedarse solo con contratos con fuente verificada.

El script genera:

candidates_for_audit.json — lista compacta de candidatos:

address

volume_token

contract_name

bluechip: true/false

Una auditoría (rápida) por contrato, llamando a contract_deep_audit.py --no-mythril.

3. Auditoría detallada de un contrato concreto

Si quieres lanzar una auditoría manual sobre una address concreta:

.venv/bin/python contract_deep_audit.py \
    --address 0x...direccion_de_contrato \
    --no-mythril


Esto generará una carpeta dedicada dentro de audit_output/ con todos los artefactos (source.sol, summary.json, reportes, etc.), lista para inspección manual o para montar un laboratorio en Hardhat/Foundry.

Resultados y artefactos clave

scanner_<token>.json
Mapa general de la actividad de ese token en el rango de bloques:

quién lo usa,

con qué volumen,

qué contratos muestran opcodes peligrosos.

candidates_for_audit.json
Lista de contratos con mayor potencial de estudio de seguridad:

volumen significativo,

opcodes peligrosos,

fuente verificada,

etiqueta bluechip para identificar protocolos grandes vs. contratos más “desconocidos”.

audit_output/<address>/summary.json
Resumen machine-friendly por contrato:

risk_flags

design_flags

oracle_flags

funciones críticas detectadas (ej. deposit, withdraw, transferOwnership, upgradeTo, etc.).

estado de Slither/Mythril (ejecutado, error, timeout).

Estos archivos son buena base tanto para análisis manual como para seguir construyendo herramientas más avanzadas (por ejemplo, dashboards o reportes automatizados).

Limitaciones y posibles mejoras

Este repositorio está diseñado como prototipo funcional y base de aprendizaje, no como producto final:

No hay aún:

caché local para eth_getCode / getsourcecode,

rotación de múltiples RPCs para evitar rate limits,

integración directa con marcos de testing (Hardhat/Foundry) dentro del propio repo.

Las heurísticas son intencionalmente simples (búsqueda de opcodes, patrones en texto fuente) y pueden generar falsos positivos/negativos.

Posibles extensiones:

Cacheo de respuestas (ej. SQLite o JSON) para reusar resultados en distintos runs.

Rotación de RPCs (ETH_RPC_URLS) y backoff exponencial si hay errores 429 o timeouts.

Exportar automáticamente los contratos más interesantes como “labs” listos para Hardhat/Foundry.

Añadir tests unitarios y de integración CI (por ejemplo, escaneo de un rango pequeño de bloques conocido con contratos verificados).

Nota final

Este proyecto se pensó como una pieza de portafolio para roles relacionados con:

seguridad de smart contracts / DeFi,

data engineering on-chain,

desarrollo de tooling para auditoría.