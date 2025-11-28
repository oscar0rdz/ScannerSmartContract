# ScannerUsdt — Pipeline Ligero para Descubrir y Auditar Contratos ERC-20 Activos

Bueno queria  aprender y porbar que tan efectiva y efciente era la utomatizaciond e procesos de pruebas de seguridad en Smarts Cotracts : **analizar qué contratos están moviendo tokens en la red Ethereum y evaluar rápidamente si representan un riesgo real**.

ScannerUsdt reúne un conjunto de herramientas en Python que automatizan tres tareas clave del trabajo de un analista DeFi junior:

1. **Descubrir actividad on-chain relevante** (escaneo de eventos ERC-20).  
2. **Priorizar contratos según riesgo y volumen**.  
3. **Lanzar auditorías rápidas y reproducibles** (bytecode + fuente + heurísticas + Slither/Mythril opcionales).

---

## Demo viusual  

Espacio reservado para el GIF del flujo completo:

<p align="center">
  <img src="docs/demo.gif" alt="Demo ScannerUsdt" style="max-width: 900px; width: 100%; height: auto;">
</p>

---

##  En lo que me quise enfocar con eston fue en probar y entender 

- Seguridad de smart contracts / auditoría DeFi  
- Data engineering on-chain  
- Desarrollo de tooling para análisis de contratos  

El   resultado del proyecto muestra:

###  Manejo directo de datos on-chain
- JSON-RPC  
- Logs de eventos Transfer  
- Bytecode desde RPC  
- Queries a Etherscan v2  

### Criterio de seguridad aplicado
Se identifican patrones de riesgo frecuentes:
- delegatecall  
- selfdestruct  
- tx.origin  
- inline assembly  
- bucles no acotados  
- timestamp y balance dependiente  

###  Pipeline reproducible
1. Descubrimiento (scanner)  
2. Priorización (volumen + opcodes peligrosos)  
3. Auditoría rápida  

---

# Estructura del Proyecto

### token_transfer_scanner.py
- Escaneo multi-token (USDT, USDC, DAI, WETH)  
- Obtención de eventos  
- Determinación de contratos  
- Extracción de opcodes peligrosos  

### filter_and_audit_from_scanner.py
- Filtrado por volumen mínimo  
- Verificación en Etherscan v2  
- Clasificación bluechip / no bluechip  
- Ejecución de auditorías rápidas  

### contract_deep_audit.py
- Descarga y guardado de source/ABI/metadata  
- Heurísticas sobre bytecode y fuente  
- Detección de funciones críticas  
- Integración opcional con Slither y Mythril  

### env_utils.py
Utilidad para cargar `.env` y ejecutar comandos con variables correctas.

### audit_output/
Salida automatizada por contrato auditado:
- source.sol  
- abi.json  
- metadata.json  
- summary.json  
- slither_report.json (opcional)  
- mythril_report.json (opcional)  

---

# Requisitos

### Entorno
Python 3.10+  

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Variables de entorno `.env`

```
ETH_RPC_URL=""
ETHERSCAN_API_KEY=""
ETHERSCAN_CHAIN_ID=1

SLITHER_CMD="slither"
MYTHRIL_CMD="myth"
MYTHRIL_ENABLED=0
MYTHRIL_DEPTH=8
MYTHRIL_TIMEOUT_SECS=120
```

---

# Flujo de Uso

### 1. Escanear actividad de un token

```
.venv/bin/python token_transfer_scanner.py --token usdt --blocks-back 3000 --limit 200 > scanner_usdt.json
```

### 2. Filtrar contratos

```
.venv/bin/python filter_and_audit_from_scanner.py scanner_usdt.json --min-volume 1000 --max 20
```

### 3. Auditoría manual

```
.venv/bin/python contract_deep_audit.py --address 0x... --no-mythril
```

---

# Resultados

### scanner_<token>.json
Mapa general de actividad del token.

### candidates_for_audit.json
Lista priorizada con:
- volumen  
- fuente verificada  
- flags de riesgo  

### audit_output/<address>/summary.json
Resumen detallado:
- risk_flags  
- oracle_flags  
- design_flags  
- funciones críticas  

---

# Cuestiones a pulir  

### Limitaciones:

- Heurísticas simples  
- Sin integración interna con Hardhat/Foundry  

### Mejoras futuras:

- Rotación de RPCs  
- Export de laboratorios para Foundry  
- Tests unitarios  
- y escalar 
---

# Nota Final

 lo que quise hacer con este proyetco fue
 irecatuar con la automatizacion de pruebas de seguridad en SC :
- datos on-chain  
- auditoría ligera  
- tooling DeFi  
- habilidad para construir pipelines claros y reproducibles  
