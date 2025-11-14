#!/usr/bin/env python3
"""
usdt_contract_scanner.py

Escáner simple para encontrar contratos que interactúan con USDT en Ethereum,
clasificarlos y marcar indicios de riesgo básicos (incluyendo patrones de oráculos).

Requisitos:
    pip install -r requirements.txt

Variables de entorno (en .env o exportadas):
    ETHERSCAN_API_KEY  -> API key de https://etherscan.io/apis
    ETH_RPC_URL        -> URL de nodo Ethereum (Infura, Alchemy, nodo propio, etc.)
                          Ejemplo: https://mainnet.infura.io/v3/TU_PROJECT_ID
    ETHERSCAN_CHAIN_ID -> ID de cadena para la API V2 de Etherscan (1 = mainnet)

Uso básico:
    python usdt_contract_scanner.py
    python usdt_contract_scanner.py --blocks-back 3000 --limit 20
"""

import os
import sys
import json
import time
import argparse
from typing import Any, Dict, List, Optional, Tuple

import requests

from env_utils import load_project_env

# Cargar variables desde .env (si existe)
load_project_env()

# Dirección oficial de USDT (Tether) en Ethereum mainnet (minúsculas)
USDT_ADDRESS = "0xdac17f958d2ee523a2206206994597c13d831ec7".lower()
# keccak256("Transfer(address,address,uint256)")
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
USDT_DECIMALS = 6

ETHERSCAN_URL = "https://api.etherscan.io/v2/api"


# -------------------- utilidades básicas -------------------- #

def env_or_die(name: str, default: Optional[str] = None) -> str:
    """Obtiene una variable de entorno o termina el programa si no existe."""
    value = os.getenv(name, default)
    if value is None or value == "":
        print(f"[ERROR] Falta variable de entorno: {name}", file=sys.stderr)
        sys.exit(1)
    return value


def parse_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw, 0)
    except ValueError:
        print(f"[ERROR] Variable de entorno inválida {name}: {raw}", file=sys.stderr)
        sys.exit(1)


def rpc_call(rpc_url: str, method: str, params: List[Any]) -> Any:
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    }
    resp = requests.post(rpc_url, json=payload, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data["result"]


def get_latest_block(rpc_url: str) -> int:
    result = rpc_call(rpc_url, "eth_blockNumber", [])
    return int(result, 16)


def is_hex(s: str) -> bool:
    return isinstance(s, str) and s.startswith("0x")


def parse_int_maybe_hex(s: str) -> int:
    if is_hex(s):
        hex_body = s[2:]
        if not hex_body:
            return 0
        return int(s, 16)
    return int(s)


def topic_to_address(topic: str) -> str:
    """
    topics vienen como 0x + 64 hex; la dirección es los últimos 40 caracteres.
    """
    if not isinstance(topic, str) or not topic.startswith("0x") or len(topic) < 42:
        return topic.lower()
    return "0x" + topic[-40:].lower()


# -------------------- Etherscan: logs USDT -------------------- #

def fetch_usdt_logs(
    etherscan_key: str,
    from_block: int,
    to_block: int,
    page_size: int = 1000,
    max_pages: int = 5,
    chain_id: int = 1,
) -> List[Dict[str, Any]]:
    """
    Descarga logs de Transfer de USDT desde Etherscan en un rango de bloques.

    IMPORTANTE:
        - No filtra por volumen: trae lo que haya en ese rango.
        - page_size y max_pages controlan cuántos logs máximos bajamos.
    """
    all_logs: List[Dict[str, Any]] = []
    page = 1

    while page <= max_pages:
        params = {
            "module": "logs",
            "action": "getLogs",
            "fromBlock": str(from_block),
            "toBlock": str(to_block),
            "address": USDT_ADDRESS,
            "topic0": TRANSFER_TOPIC,
            "page": page,
            "offset": page_size,
            "chainId": chain_id,
            "apikey": etherscan_key,
        }
        resp = requests.get(ETHERSCAN_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        status = data.get("status", "0")
        message = data.get("message", "")
        result = data.get("result", [])

        if status == "0":
            # "No records found" -> sin logs, terminamos
            if "No records" in message:
                break
            # Otro error -> mostrar y salir
            raise RuntimeError(f"Etherscan error: {message} | {result}")

        if not isinstance(result, list) or not result:
            break

        all_logs.extend(result)

        # Si recibimos menos que page_size, ya no hay más páginas
        if len(result) < page_size:
            break

        page += 1
        # Pequeña pausa para no pegarle tan duro al API free
        time.sleep(0.2)

    return all_logs


def parse_usdt_transfers(raw_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convierte logs crudos en una lista de transfers con from, to, valor, etc."""
    transfers: List[Dict[str, Any]] = []
    for log in raw_logs:
        topics = log.get("topics", [])
        if len(topics) < 3:
            continue

        from_addr = topic_to_address(topics[1])
        to_addr = topic_to_address(topics[2])

        data_hex = log.get("data", "0x0")
        value_raw = int(data_hex, 16)
        value_usdt = value_raw / (10 ** USDT_DECIMALS)

        tx_hash = log.get("transactionHash") or log.get("transactionhash")
        block_number = parse_int_maybe_hex(log.get("blockNumber", "0"))
        log_index = parse_int_maybe_hex(log.get("logIndex", "0"))

        transfers.append(
            {
                "from": from_addr,
                "to": to_addr,
                "value_raw": value_raw,
                "value_usdt": value_usdt,
                "tx_hash": tx_hash,
                "block_number": block_number,
                "log_index": log_index,
            }
        )
    return transfers


# -------------------- Identificar contratos y estadísticos -------------------- #

def get_code(rpc_url: str, address: str) -> str:
    """Devuelve el bytecode de un address en 'latest'."""
    result = rpc_call(rpc_url, "eth_getCode", [address, "latest"])
    return result  # string hex


def build_contract_stats(
    rpc_url: str,
    transfers: List[Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    """
    Devuelve:
        stats_por_contrato: {address -> {interactions, volume_usdt, first_block, last_block}}
        bytecodes: {address -> bytecode}

    No filtra por 'mínimo volumen'; todos los contratos que aparecen en algún
    transfer de USDT entran al diccionario de stats.
    """
    # 1) direcciones únicas usando USDT
    addrs = set()
    for t in transfers:
        addrs.add(t["from"])
        addrs.add(t["to"])

    # 2) filtrar solo contratos y guardar bytecode
    contract_addrs: List[str] = []
    bytecodes: Dict[str, str] = {}
    for addr in addrs:
        try:
            code = get_code(rpc_url, addr)
            if isinstance(code, str) and code != "0x":
                contract_addrs.append(addr)
                bytecodes[addr] = code
        except Exception as e:
            print(f"[WARN] Error al consultar code de {addr}: {e}", file=sys.stderr)

    # 3) estadísticos por contrato
    stats: Dict[str, Dict[str, Any]] = {}
    for t in transfers:
        for role in ("from", "to"):
            addr = t[role]
            if addr not in contract_addrs:
                continue
            s = stats.setdefault(
                addr,
                {
                    "interactions": 0,
                    "volume_usdt": 0.0,
                    "first_block": t["block_number"],
                    "last_block": t["block_number"],
                },
            )
            s["interactions"] += 1
            s["volume_usdt"] += abs(t["value_usdt"])
            s["first_block"] = min(s["first_block"], t["block_number"])
            s["last_block"] = max(s["last_block"], t["block_number"])

    return stats, bytecodes


# -------------------- Etherscan: ABI y source -------------------- #

def etherscan_get_abi(etherscan_key: str, address: str) -> Optional[List[Dict[str, Any]]]:
    params = {
        "module": "contract",
        "action": "getabi",
        "address": address,
        "apikey": etherscan_key,
    }
    resp = requests.get(ETHERSCAN_URL, params=params, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "1":
        return None
    abi_str = data.get("result")
    try:
        abi = json.loads(abi_str)
        if isinstance(abi, list):
            return abi
    except Exception:
        return None
    return None


def etherscan_get_source(etherscan_key: str, address: str) -> Optional[str]:
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": etherscan_key,
    }
    resp = requests.get(ETHERSCAN_URL, params=params, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    result = data.get("result")
    if not isinstance(result, list) or not result:
        return None
    entry = result[0]
    source = entry.get("SourceCode")
    if not source:
        return None
    return str(source)


# -------------------- Clasificación y banderas de riesgo -------------------- #

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

    # ERC20-like
    erc20_core = {"totalSupply", "balanceOf", "transfer"}
    if erc20_core.issubset(function_names):
        tags.append("erc20_like")

    # ERC721-like
    erc721_markers = {"ownerOf", "safeTransferFrom", "tokenURI"}
    if function_names.intersection(erc721_markers):
        tags.append("erc721_like")

    # DeFi-like (lending, DEX, etc.)
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
    lname = [name.lower() for name in function_names]
    if any(any(kw in n for kw in defi_keywords) for n in lname):
        tags.append("defi_like")

    if not tags:
        tags.append("other")

    return tags


def scan_risky_patterns(bytecode: Optional[str], source: Optional[str]) -> List[str]:
    """
    Heurísticas muy simples: sólo levantan la mano,
    no significan que el contrato sea vulnerable.
    """
    flags: List[str] = []

    # Bytecode-level
    if isinstance(bytecode, str):
        low = bytecode.lower()
        # Presencia de opcodes característicos
        if "f4" in low:
            flags.append("uses_delegatecall_opcode")
        if "f2" in low:
            flags.append("uses_callcode_opcode")
        if "ff" in low:
            flags.append("can_selfdestruct_opcode")

    # Source-level
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


def scan_oracle_patterns(
    abi: Optional[List[Dict[str, Any]]],
    source: Optional[str],
) -> List[str]:
    """
    Marca contratos que parecen depender de oráculos o precios,
    para que tú los revises con más detalle (manipulación de precio, etc.).
    """
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

    # Buscar en nombres de funciones/eventos de la ABI
    if abi:
        names: List[str] = []
        for item in abi:
            name = item.get("name")
            if isinstance(name, str):
                names.append(name.lower())

        if any(
            any(kw.lower() in n for kw in oracle_keywords)
            for n in names
        ):
            flags.append("oracle_related_abi")

    # Buscar en el source code verificado
    if isinstance(source, str) and source:
        low = source.lower()
        if any(kw.lower() in low for kw in oracle_keywords):
            flags.append("oracle_related_source")

    return flags


# -------------------- MAIN -------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Escáner de contratos que interactúan con USDT en Ethereum."
    )
    parser.add_argument(
        "--blocks-back",
        type=int,
        default=int(os.getenv("BLOCKS_BACK", "3000")),
        help="Número de bloques hacia atrás desde el último bloque (por defecto 3000 o BLOCKS_BACK en .env).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=int(os.getenv("LIMIT", "20")),
        help="Número máximo de contratos a mostrar (por defecto 20 o LIMIT en .env).",
    )
    args = parser.parse_args()

    etherscan_key = env_or_die("ETHERSCAN_API_KEY")
    rpc_url = env_or_die("ETH_RPC_URL")
    chain_id = parse_int_env("ETHERSCAN_CHAIN_ID", 1)

    print("[*] Obteniendo último bloque...")
    latest_block = get_latest_block(rpc_url)
    from_block = max(0, latest_block - args.blocks_back)
    print(f"[*] Rango de bloques: {from_block} -> {latest_block}")

    print("[*] Descargando logs de Transfer de USDT desde Etherscan...")
    raw_logs = fetch_usdt_logs(
        etherscan_key, from_block, latest_block, chain_id=chain_id
    )
    print(f"[*] Logs de USDT recibidos: {len(raw_logs)}")

    transfers = parse_usdt_transfers(raw_logs)
    if not transfers:
        print("[!] No se encontraron transfers de USDT en el rango especificado.")
        return

    print("[*] Identificando contratos que usan USDT (no se filtra por volumen)...")
    stats, bytecodes = build_contract_stats(rpc_url, transfers)
    if not stats:
        print("[!] No se encontraron contratos (solo EOAs) en los transfers.")
        return

    print(f"[*] Contratos candidatos encontrados: {len(stats)}")

    # Orden preliminar por volumen USDT y nº de interacciones
    sorted_contracts = sorted(
        stats.items(),
        key=lambda kv: (kv[1]["volume_usdt"], kv[1]["interactions"]),
        reverse=True,
    )

    # Tomamos al menos 'limit' contratos; si quieres puedes subir limit desde CLI o .env
    top_contracts = sorted_contracts[: args.limit]

    print(f"[*] Enriqueciendo top {len(top_contracts)} contratos con ABI/source...\n")

    enriched: List[Dict[str, Any]] = []

    for addr, st in top_contracts:
        print(f"  -> Analizando {addr} ...")
        abi: Optional[List[Dict[str, Any]]] = None
        source: Optional[str] = None
        try:
            abi = etherscan_get_abi(etherscan_key, addr)
        except Exception as e:
            print(f"     [WARN] No se pudo obtener ABI: {e}")

        try:
            source = etherscan_get_source(etherscan_key, addr)
        except Exception as e:
            print(f"     [WARN] No se pudo obtener source: {e}")

        tags = classify_contract(abi)
        bytecode = bytecodes.get(addr)
        risk_flags = scan_risky_patterns(bytecode, source)
        risk_flags += scan_oracle_patterns(abi, source)

        enriched.append(
            {
                "address": addr,
                "stats": st,
                "tags": tags,
                "risk_flags": risk_flags,
            }
        )
        # Pausa corta para no saturar Etherscan
        time.sleep(0.2)

    print("\n================ RESUMEN DE CONTRATOS =================\n")
    for i, item in enumerate(enriched, start=1):
        addr = item["address"]
        st = item["stats"]
        tags = ", ".join(item["tags"])
        risks = ", ".join(item["risk_flags"]) if item["risk_flags"] else "ninguna bandera simple"
        print(f"[{i}] {addr}")
        print(f"    Interacciones USDT : {st['interactions']}")
        print(f"    Volumen USDT aprox : {st['volume_usdt']:.4f}")
        print(f"    Bloques actividad  : {st['first_block']} -> {st['last_block']}")
        print(f"    Tipo (tags)        : {tags}")
        print(f"    Indicios riesgo    : {risks}")
        print(f"    Etherscan          : https://etherscan.io/address/{addr}")
        print("")

    # Guardar en JSON
    out_path = "usdt_contract_scan.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2)
    print(f"[*] Resultado guardado en {out_path}")


if __name__ == "__main__":
    main()
