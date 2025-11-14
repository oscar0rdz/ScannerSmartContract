#!/usr/bin/env python3
"""
contract_deep_audit.py

Auditoría profunda de UN contrato inteligente en Ethereum:

- Descarga source+ABI+metadatos desde Etherscan.
- Obtiene bytecode y balance via RPC.
- Hace heurísticas de seguridad:
    * Reentrancy surface (llamadas externas peligrosas)
    * tx.origin, low-level calls, delegatecall, selfdestruct
    * aleatoriedad débil (block.timestamp, blockhash)
    * bucles potencialmente no acotados
    * address(this).balance usado en lógica de control
    * bloques unchecked
    * patrones relacionados con oráculos (Chainlink, priceFeed, etc.)

- Opcional: ejecuta Slither y Mythril si están instalados:
    * Slither: análisis estático con todos los detectores, genera JSON
    * Mythril: análisis simbólico sobre el bytecode, genera JSON

Salida:
    audit_output/<address>/
        source.sol
        abi.json
        metadata.json
        summary.json
        slither_report.json   (si Slither está disponible)
        mythril_report.json   (si Mythril está disponible)

Uso:
    python contract_deep_audit.py --address 0xCONTRATO
    # opcionalmente:
    python contract_deep_audit.py --address 0xCONTRATO --no-slither --no-mythril
"""

import os
import sys
import json
import time
import argparse
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import requests

from env_utils import load_project_env

# Cargar variables desde .env
load_project_env()

ETHERSCAN_URL = "https://api.etherscan.io/v2/api"
ETHERSCAN_CHAIN_ID = os.getenv("ETHERSCAN_CHAIN_ID", "1")


# -------------------- utilidades base -------------------- #

def env_or_die(name: str) -> str:
    value = os.getenv(name)
    if not value:
        print(f"[ERROR] Falta variable de entorno: {name}", file=sys.stderr)
        sys.exit(1)
    return value


def rpc_call(rpc_url: str, method: str, params: List[Any]) -> Any:
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    }
    resp = requests.post(rpc_url, json=payload, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data["result"]


def get_code(rpc_url: str, address: str) -> str:
    return rpc_call(rpc_url, "eth_getCode", [address, "latest"])


def get_balance(rpc_url: str, address: str) -> int:
    res = rpc_call(rpc_url, "eth_getBalance", [address, "latest"])
    return int(res, 16)


# -------------------- Etherscan: source + ABI + metadata -------------------- #

def fetch_etherscan_contract_info(
    etherscan_key: str,
    address: str,
) -> Tuple[Optional[str], Optional[List[Dict[str, Any]]], Dict[str, Any]]:
    """
    Usa getsourcecode para traer:
        - SourceCode
        - ABI
        - metadata (nombre, compilador, proxy, etc.)
    """
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": etherscan_key,
        "chainid": ETHERSCAN_CHAIN_ID,
    }
    resp = requests.get(ETHERSCAN_URL, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    result = data.get("result")
    if not isinstance(result, list) or not result:
        return None, None, {"raw_result": result, "status": data.get("status"), "message": data.get("message")}

    entry = result[0]

    # SourceCode: v2 also may return JSON for multi-file projects; keep raw string for now
    source_code = entry.get("SourceCode") or None
    if isinstance(source_code, str) and source_code.strip() == "":
        source_code = None

    # ABI viene como string JSON o "Contract source code not verified"
    abi_raw = entry.get("ABI") or None
    abi: Optional[List[Dict[str, Any]]] = None
    if isinstance(abi_raw, str) and abi_raw not in ("", "Contract source code not verified"):
        try:
            parsed = json.loads(abi_raw)
            if isinstance(parsed, list):
                abi = parsed
        except Exception:
            abi = None

    metadata_fields = [
        "ContractName",
        "CompilerVersion",
        "CompilerType",
        "OptimizationUsed",
        "Runs",
        "EVMVersion",
        "LicenseType",
        "Proxy",
        "Implementation",
        "SwarmSource",
        "SimilarMatch",
    ]
    metadata = {k: entry.get(k) for k in metadata_fields}
    metadata["raw_entry"] = entry

    return source_code, abi, metadata


# -------------------- Clasificación, oráculos y heurísticas -------------------- #

def classify_contract(abi: Optional[List[Dict[str, Any]]]) -> List[str]:
    if not abi:
        return ["unknown"]

    function_names = set()
    event_names = set()

    for item in abi:
        t = item.get("type")
        if t == "function":
            function_names.add(item.get("name", ""))
        elif t == "event":
            event_names.add(item.get("name", ""))

    tags: List[str] = []

    erc20_core = {"totalSupply", "balanceOf", "transfer"}
    if erc20_core.issubset(function_names):
        tags.append("erc20_like")

    erc721_markers = {"ownerOf", "safeTransferFrom", "tokenURI"}
    if function_names.intersection(erc721_markers):
        tags.append("erc721_like")

    defi_keywords = [
        "swap",
        "deposit",
        "withdraw",
        "borrow",
        "repay",
        "flash",
        "liquidate",
        "stake",
        "unstake",
        "addLiquidity",
        "removeLiquidity",
    ]
    lname = [n.lower() for n in function_names]
    if any(any(kw in n for kw in defi_keywords) for n in lname):
        tags.append("defi_like")

    if not tags:
        tags.append("other")

    return tags


def scan_oracle_patterns(
    abi: Optional[List[Dict[str, Any]]],
    source: Optional[str],
) -> List[str]:
    flags: List[str] = []

    oracle_keywords = [
        "oracle",
        "pricefeed",
        "priceFeed",
        "AggregatorV3Interface",
        "latestrounddata",
        "latestRoundData",
        "getassetprice",
        "getAssetPrice",
        "getprice",
        "getPrice",
        "pricepershare",
        "pricePerShare",
        "exchangerate",
        "exchangeRate",
        "exchangeratestored",
        "exchangeRateStored",
    ]

    if abi:
        names: List[str] = []
        for item in abi:
            name = item.get("name")
            if isinstance(name, str):
                names.append(name.lower())
        if any(any(kw.lower() in n for kw in oracle_keywords) for n in names):
            flags.append("oracle_related_abi")

    if isinstance(source, str) and source:
        low = source.lower()
        if any(kw.lower() in low for kw in oracle_keywords):
            flags.append("oracle_related_source")

    return flags


def scan_risky_patterns(bytecode: Optional[str], source: Optional[str]) -> List[str]:
    """
    Bandera cosas que merecen inspección manual (no prueba de vulnerabilidad).
    """
    flags: List[str] = []

    # Bytecode
    if isinstance(bytecode, str):
        low = bytecode.lower()
        if "f4" in low:
            flags.append("uses_delegatecall_opcode")
        if "f2" in low:
            flags.append("uses_callcode_opcode")
        if "ff" in low:
            flags.append("can_selfdestruct_opcode")

    # Fuente
    if isinstance(source, str):
        s = source
        if "tx.origin" in s:
            flags.append("uses_tx_origin")
        if ".call.value(" in s or ".call{value" in s:
            flags.append("raw_call_value_pattern")
        if "delegatecall(" in s:
            flags.append("delegatecall_in_source")
        if "assembly {" in s or "inline assembly" in s:
            flags.append("uses_inline_assembly")

    return flags


def scan_design_smells(source: Optional[str]) -> List[str]:
    """
    Otras banderas de diseño:
        - aleatoriedad débil
        - uso de block.timestamp / blockhash
        - bucles sobre arrays .length
        - address(this).balance en lógica
        - bloques unchecked (posibles overflows intencionales)
    """
    flags: List[str] = []
    if not isinstance(source, str) or not source:
        return flags

    low = source.lower()

    # Aleatoriedad débil
    if "block.timestamp" in source or "now" in source:
        flags.append("uses_block_timestamp")
    if "blockhash(" in source:
        flags.append("uses_blockhash")

    # address(this).balance
    if "address(this).balance" in source:
        flags.append("depends_on_contract_balance")

    # Bucles con .length (posibles loops no acotados)
    if ".length" in source and "for (" in source:
        flags.append("for_loops_over_dynamic_length")

    # unchecked blocks (posibles overflows intencionales)
    if "unchecked {" in low:
        flags.append("uses_unchecked_blocks")

    return flags


def extract_potentially_critical_functions(source: Optional[str]) -> List[Dict[str, Any]]:
    """
    Busca funciones public/external cuyos nombres sugieren operaciones críticas.
    Simplemente ayuda a saber qué revisar primero.
    """
    if not isinstance(source, str):
        return []

    critical_keywords = [
        "withdraw",
        "deposit",
        "claim",
        "liquidate",
        "borrow",
        "repay",
        "mint",
        "burn",
        "upgrade",
        "pause",
        "unpause",
        "setowner",
        "transferownership",
    ]
    lines = source.splitlines()
    results: List[Dict[str, Any]] = []

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("function "):
            continue
        if "public" not in stripped and "external" not in stripped:
            continue

        # Nombre de la función: después de "function " hasta el primer "("
        try:
            after = stripped.split("function", 1)[1].strip()
            name = after.split("(", 1)[0].strip()
        except Exception:
            continue

        lname = name.lower()
        if any(kw in lname for kw in critical_keywords):
            results.append(
                {
                    "name": name,
                    "line": idx,
                    "signature_line": line.strip(),
                }
            )

    return results


# -------------------- Slither y Mythril por CLI -------------------- #

def run_slither(out_dir: str, source_path: str) -> Dict[str, Any]:
    """
    Ejecuta Slither sobre source_path y genera slither_report.json en out_dir.
    Devuelve un pequeño resumen de severidades si el JSON es parseable.
    """
    cmd = os.getenv("SLITHER_CMD", "slither")
    json_path = os.path.join(out_dir, "slither_report.json")
    print(f"[*] Ejecutando Slither: {cmd} {source_path} --json {json_path}")

    try:
        proc = subprocess.run(
            [cmd, source_path, "--json", json_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print("[WARN] Slither no encontrado en el sistema. Omite análisis Slither.")
        return {"enabled": False, "error": "slither_not_found"}

    if proc.returncode != 0:
        print("[WARN] Slither devolvió código distinto de 0 (revisar stdout/stderr en consola).")
        return {"enabled": True, "error": "slither_failed", "returncode": proc.returncode}

    # Intentar resumir severidades a partir del JSON
    summary = {"enabled": True, "error": None, "high": 0, "medium": 0, "low": 0, "informational": 0}
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        detectors = data.get("results", {}).get("detectors", [])
        for d in detectors:
            impact = (d.get("impact") or "").lower()
            if impact == "high":
                summary["high"] += 1
            elif impact == "medium":
                summary["medium"] += 1
            elif impact == "low":
                summary["low"] += 1
            elif impact == "informational":
                summary["informational"] += 1
    except Exception as e:
        summary["error"] = f"parse_error: {e}"

    return summary


def run_mythril(out_dir: str, bytecode: str) -> Dict[str, Any]:
    """
    Ejecuta Mythril sobre el bytecode y genera mythril_report.json en out_dir.
    Solo guarda el JSON; no intenta interpretar el formato interno.
    """
    cmd = os.getenv("MYTHRIL_CMD", "myth")
    json_path = os.path.join(out_dir, "mythril_report.json")
    print(f"[*] Ejecutando Mythril: {cmd} analyze -c <bytecode> -o jsonv2 -j {json_path}")

    try:
        proc = subprocess.run(
            [cmd, "analyze", "-c", bytecode, "-o", "jsonv2", "-j", json_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print("[WARN] Mythril no encontrado en el sistema. Omite análisis Mythril.")
        return {"enabled": False, "error": "mythril_not_found"}

    if proc.returncode != 0:
        print("[WARN] Mythril devolvió código distinto de 0 (revisar stdout/stderr en consola).")
        return {"enabled": True, "error": "mythril_failed", "returncode": proc.returncode}

    return {"enabled": True, "error": None}


# -------------------- MAIN -------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Auditoría profunda de un contrato inteligente en Ethereum."
    )
    parser.add_argument(
        "--address",
        required=True,
        help="Dirección del contrato (0x...).",
    )
    parser.add_argument(
        "--output-root",
        default="audit_output",
        help="Carpeta raíz donde se guardarán los resultados (por defecto audit_output).",
    )
    parser.add_argument(
        "--no-slither",
        action="store_true",
        help="No ejecutar Slither (solo heurísticas internas).",
    )
    parser.add_argument(
        "--no-mythril",
        action="store_true",
        help="No ejecutar Mythril (solo heurísticas internas).",
    )
    args = parser.parse_args()

    addr = args.address.strip()
    if not addr.startswith("0x") or len(addr) < 10:
        print("[ERROR] Dirección inválida.", file=sys.stderr)
        sys.exit(1)
    addr = addr.lower()

    etherscan_key = env_or_die("ETHERSCAN_API_KEY")
    rpc_url = env_or_die("ETH_RPC_URL")

    out_dir = os.path.join(args.output_root, addr)
    os.makedirs(out_dir, exist_ok=True)

    print(f"[*] Analizando contrato {addr}")
    print("[*] Descargando fuente/ABI/metadata desde Etherscan...")
    source_code, abi, metadata = fetch_etherscan_contract_info(etherscan_key, addr)

    if source_code is None:
        print("[WARN] Contrato sin código verificado en Etherscan o sin SourceCode.")
    else:
        source_path = os.path.join(out_dir, "source.sol")
        with open(source_path, "w", encoding="utf-8") as f:
            f.write(source_code)
        print(f"[*] Source guardado en {source_path}")

    if abi is not None:
        abi_path = os.path.join(out_dir, "abi.json")
        with open(abi_path, "w", encoding="utf-8") as f:
            json.dump(abi, f, indent=2)
        print(f"[*] ABI guardado en {abi_path}")

    print("[*] Obteniendo bytecode y balance on-chain...")
    bytecode = get_code(rpc_url, addr)
    balance_wei = get_balance(rpc_url, addr)

    # Clasificación y banderas
    tags = classify_contract(abi)
    oracle_flags = scan_oracle_patterns(abi, source_code)
    risk_flags = scan_risky_patterns(bytecode, source_code)
    design_flags = scan_design_smells(source_code)
    critical_fns = extract_potentially_critical_functions(source_code)

    is_contract = isinstance(bytecode, str) and bytecode != "0x"
    bytecode_len = len(bytecode) // 2 if isinstance(bytecode, str) else 0

    # Metadata adicional
    meta = {
        "address": addr,
        "is_contract": is_contract,
        "bytecode_length_bytes": bytecode_len,
        "balance_wei": balance_wei,
        "balance_eth_approx": balance_wei / (10 ** 18),
        "etherscan_metadata": metadata,
        "classification_tags": tags,
        "oracle_flags": oracle_flags,
        "risk_flags": risk_flags,
        "design_flags": design_flags,
        "critical_functions": critical_fns,
    }

    metadata_path = os.path.join(out_dir, "metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"[*] Metadata y clasificación guardadas en {metadata_path}")

    # Ejecutar Slither/Mythril si procede
    slither_summary: Dict[str, Any] = {}
    mythril_summary: Dict[str, Any] = {}

    if not args.no_slither and source_code is not None:
        slither_summary = run_slither(out_dir, source_path)
    else:
        slither_summary = {"enabled": False, "error": "disabled_or_no_source"}

    if not args.no_mythril and isinstance(bytecode, str) and bytecode != "0x":
        mythril_summary = run_mythril(out_dir, bytecode)
    else:
        mythril_summary = {"enabled": False, "error": "disabled_or_no_bytecode"}

    summary = {
        "address": addr,
        "tags": tags,
        "oracle_flags": oracle_flags,
        "risk_flags": risk_flags,
        "design_flags": design_flags,
        "critical_functions": critical_fns,
        "slither_summary": slither_summary,
        "mythril_summary": mythril_summary,
    }

    summary_path = os.path.join(out_dir, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"[*] Resumen final guardado en {summary_path}")

    print("\n=========== RESUMEN EN CONSOLA ===========\n")
    print(f"Contrato         : {addr}")
    print(f"Es contrato?     : {is_contract}")
    print(f"Balance (ETH)    : {meta['balance_eth_approx']:.6f}")
    print(f"Tags tipo        : {', '.join(tags)}")
    print(f"Oracle flags     : {', '.join(oracle_flags) if oracle_flags else 'ninguno'}")
    print(f"Risk flags       : {', '.join(risk_flags) if risk_flags else 'ninguno'}")
    print(f"Diseño flags     : {', '.join(design_flags) if design_flags else 'ninguno'}")
    print(f"Funciones críticas detectadas: {len(critical_fns)}")

    if critical_fns:
        for fn in critical_fns:
            print(f"  - {fn['name']} (línea {fn['line']})")

    print("\nSlither:")
    print(f"  Activado       : {slither_summary.get('enabled')}")
    if slither_summary.get("enabled"):
        if slither_summary.get("error") is None:
            print(
                f"  High={slither_summary.get('high', 0)}, "
                f"Medium={slither_summary.get('medium', 0)}, "
                f"Low={slither_summary.get('low', 0)}, "
                f"Info={slither_summary.get('informational', 0)}"
            )
        else:
            print(f"  Error          : {slither_summary.get('error')}")

    print("\nMythril:")
    print(f"  Activado       : {mythril_summary.get('enabled')}")
    if mythril_summary.get("enabled"):
        print(f"  Error          : {mythril_summary.get('error')}")

    print(f"\n[*] Carpeta de auditoría lista en: {out_dir}")


if __name__ == "__main__":
    main()

