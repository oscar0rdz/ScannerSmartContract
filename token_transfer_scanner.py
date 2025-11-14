#!/usr/bin/env python3
"""
token_transfer_scanner.py

Escanea eventos Transfer de un token ERC-20 (USDT, USDC, DAI, WETH) en un rango
de bloques, identifica contratos que interactúan con ese token y calcula:

- interacciones (número de veces que aparece)
- volumen total movido (en unidades del token)
- primer y último bloque donde aparece
- risk_flags basados en el bytecode del contrato:
    * uses_delegatecall_opcode
    * uses_callcode_opcode
    * can_selfdestruct_opcode

Salida: imprime un JSON de una lista de objetos.
"""

import argparse
import json
import os
import time
from typing import Any, Dict, List

import requests
from env_utils import load_project_env


TOKENS = {
    # Mainnet Ethereum
    "usdt": {
        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "decimals": 6,
    },
    "usdc": {
        "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "decimals": 6,
    },
    "dai": {
        "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "decimals": 18,
    },
    "weth": {
        "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        "decimals": 18,
    },
}


def load_env_and_rpc() -> Dict[str, str]:
    load_project_env()
    rpc_url = os.getenv("ETH_RPC_URL")
    etherscan_key = os.getenv("ETHERSCAN_API_KEY")
    chain_id = os.getenv("ETHERSCAN_CHAIN_ID", "1")
    if not rpc_url:
        raise RuntimeError("Falta ETH_RPC_URL en .env")
    return {"rpc_url": rpc_url, "etherscan_key": etherscan_key, "chain_id": chain_id}


def get_transfer_topic() -> str:
    # keccak256("Transfer(address,address,uint256)")
    return "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def rpc_call(rpc_url: str, method: str, params: List[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    resp = requests.post(rpc_url, json=payload, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data["result"]


def analyze_risk_flags(bytecode: str) -> List[str]:
    flags: List[str] = []
    low = bytecode.lower()
    if "f4" in low:
        flags.append("uses_delegatecall_opcode")
    if "f2" in low:
        flags.append("uses_callcode_opcode")
    if "ff" in low:
        flags.append("can_selfdestruct_opcode")
    return flags


def scan_token_transfers(
    token_symbol: str,
    blocks_back: int,
    limit: int,
) -> List[Dict[str, Any]]:
    token = TOKENS[token_symbol]
    token_address = token["address"].lower()
    decimals = token["decimals"]

    env = load_env_and_rpc()
    rpc_url = env["rpc_url"]
    etherscan_key = env.get("etherscan_key")
    chain_id = env.get("chain_id", "1")

    latest_block_hex = rpc_call(rpc_url, "eth_blockNumber", [])
    latest_block = int(latest_block_hex, 16)
    from_block = max(0, latest_block - blocks_back)
    to_block = latest_block

    print(
        f"[*] Escaneando {token_symbol.upper()} desde bloque {from_block} hasta {to_block} (RPC: {rpc_url})"
    )

    transfer_topic = get_transfer_topic()

    # Use Etherscan V2 logs endpoint with pagination
    all_logs: List[Dict[str, Any]] = []
    page = 1
    page_size = 1000
    max_pages = 10
    etherscan_url = os.getenv("ETHERSCAN_URL", "https://api.etherscan.io/v2/api")

    while page <= max_pages:
        params = {
            "module": "logs",
            "action": "getLogs",
            "fromBlock": str(from_block),
            "toBlock": str(to_block),
            "address": token_address,
            "topic0": transfer_topic,
            "page": page,
            "offset": page_size,
            "apikey": etherscan_key,
            "chainid": chain_id,
        }
        resp = requests.get(etherscan_url, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("status", "0")
        message = data.get("message", "")
        result = data.get("result", [])
        if status == "0":
            if "No records" in message:
                break
            raise RuntimeError(f"Etherscan error: {message} | {result}")

        if not isinstance(result, list) or not result:
            break

        all_logs.extend(result)

        if len(result) < page_size:
            break

        page += 1
        time.sleep(0.2)

    print(f"[*] Encontrados {len(all_logs)} logs Transfer de {token_symbol.upper()} en el rango.")

    # Agregar volumen por dirección (tanto from como to, si son contratos)
    counters: Dict[str, Dict[str, Any]] = {}

    for log in all_logs:
        block_number = int(log.get("blockNumber", "0"), 16)
        topics = log.get("topics", [])
        data = log.get("data", "0x0")

        # topics[1] = from, topics[2] = to
        if len(topics) < 3:
            continue

        # topics elements are hex strings like '0x000...'
        from_topic = topics[1]
        to_topic = topics[2]
        try:
            from_addr = "0x" + from_topic[-40:]
            to_addr = "0x" + to_topic[-40:]
        except Exception:
            continue

        value_int = int(data, 16)
        value = value_int / (10 ** decimals)

        for addr in (from_addr, to_addr):
            # Saltar el propio token
            if addr.lower() == token_address.lower():
                continue

            # Agregar/actualizar estadísticas
            key = addr.lower()
            stats = counters.get(key)
            if stats is None:
                stats = {
                    "interactions": 0,
                    "volume_token": 0.0,
                    "first_block": block_number,
                    "last_block": block_number,
                }
                counters[key] = stats

            stats["interactions"] += 1
            stats["volume_token"] += value
            stats["first_block"] = min(stats["first_block"], block_number)
            stats["last_block"] = max(stats["last_block"], block_number)

    print(f"[*] Direcciones únicas con {token_symbol.upper()}: {len(counters)}")

    # Ahora filtramos (solo top candidatos por volumen) y calculamos risk_flags via RPC
    # Esto evita hacer RPC `eth_getCode` para cientos/miiles de direcciones.
    results: List[Dict[str, Any]] = []
    rpc_url = load_env_and_rpc()["rpc_url"]

    # Ordenar direcciones por volumen y tomar una ventana razonable para chequear bytecode
    sorted_addrs = sorted(counters.items(), key=lambda kv: kv[1]["volume_token"], reverse=True)
    max_checks = max(limit * 5, 200)
    candidates_to_check = sorted_addrs[: max_checks]

    for addr, stats in candidates_to_check:
        checksum = addr if addr.startswith("0x") else "0x" + addr
        try:
            code_hex = rpc_call(rpc_url, "eth_getCode", [checksum, "latest"]) or "0x"
        except Exception as e:
            print(f"[WARN] Error al consultar code de {checksum}: {e}")
            continue

        if not code_hex or code_hex == "0x":
            continue
        # code_hex may be '0x...' or raw hex string; analyze as string
        risk_flags = analyze_risk_flags(code_hex)

        results.append(
            {
                "address": checksum,
                "stats": {
                    "interactions": stats["interactions"],
                    "volume_token": stats["volume_token"],
                    "first_block": stats["first_block"],
                    "last_block": stats["last_block"],
                },
                "tags": ["unknown"],
                "risk_flags": risk_flags,
            }
        )

    # Ordenar por volumen descendente y cortar por limit
    results.sort(key=lambda x: x["stats"]["volume_token"], reverse=True)
    results = results[:limit]

    print(f"[*] Top {len(results)} contratos candidatos para {token_symbol.upper()} listo.")
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Escanea Transfer de USDT/USDC/DAI/WETH y genera lista de contratos candidatos."
    )
    parser.add_argument(
        "--token",
        choices=list(TOKENS.keys()),
        default="usdt",
        help="Token a escanear (usdt, usdc, dai, weth). Por defecto usdt.",
    )
    parser.add_argument(
        "--blocks-back",
        type=int,
        default=3000,
        help="Rango de bloques hacia atrás desde el último bloque. Por defecto 3000.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Número máximo de contratos en el output. Por defecto 50.",
    )
    args = parser.parse_args()

    # Ensure env is loaded; functions load it again as needed
    load_project_env()

    results = scan_token_transfers(
        token_symbol=args.token,
        blocks_back=args.blocks_back,
        limit=args.limit,
    )

    # Imprimir JSON en stdout
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
