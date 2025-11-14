#!/usr/bin/env python3
"""
filter_and_audit_from_scanner.py

Filtra la salida del scanner y lanza auditorías (contract_deep_audit.py).
"""

import argparse
import json
import os
import subprocess
from typing import Any, Dict, List, Tuple

from env_utils import load_project_env
from contract_deep_audit import fetch_etherscan_contract_info


BLUECHIP_KEYWORDS = [
    "uniswap",
    "aave",
    "compound",
    "curve",
    "balancer",
    "maker",
    "lido",
    "yearn",
    "sushiswap",
    "frax",
    "stargate",
    "paraswap",
    "1inch",
    "pancake",
]

STRICT_RISK_SET = {"uses_delegatecall_opcode", "can_selfdestruct_opcode"}


def is_bluechip(contract_name: str) -> bool:
    name = (contract_name or "").lower()
    return any(kw in name for kw in BLUECHIP_KEYWORDS)


def pick_interesting_candidates(
    scanner_data: List[Dict[str, Any]],
    etherscan_key: str,
    min_volume: float,
    max_candidates: int,
) -> List[Tuple[str, float, str, bool]]:
    """
    Devuelve lista de (address, volume_token, contract_name, is_bluechip)
    para contratos que cumplen:

      - volume_token >= min_volume
      - risk_flags contiene STRICT_RISK_SET (delegatecall + selfdestruct)
      - fuente verificada en Etherscan (tiene SourceCode)

    Bluechips no se descartan, solo se marcan (is_bluechip=True).
    """
    selected: List[Tuple[str, float, str, bool]] = []

    for item in scanner_data:
        addr = item.get("address")
        stats = item.get("stats") or {}
        volume = float(stats.get("volume_token", 0.0))
        risk_flags = item.get("risk_flags") or []

        if not addr or not addr.startswith("0x"):
            continue

        # 1) Volumen mínimo
        if volume < min_volume:
            continue

        # 2) Riesgo estricto: delegatecall + selfdestruct
        risk_set = set(risk_flags)
        if not STRICT_RISK_SET.issubset(risk_set):
            continue

        # 3) Preguntar a Etherscan si está verificado (API v2)
        source, abi, meta = fetch_etherscan_contract_info(etherscan_key, addr)
        if source is None:
            # Sin SourceCode -> no sirve para checklist de funciones críticas
            continue

        contract_name = (meta.get("ContractName") or "").strip()
        blue = is_bluechip(contract_name)

        label = "[BLUECHIP]" if blue else "[NON-BLUECHIP]"
        print(
            f"[OK] Candidato {label}: {addr} | volumen={volume:.4f} | name='{contract_name}' "
            f"| risk_flags={risk_flags}"
        )

        selected.append((addr, volume, contract_name, blue))

        if len(selected) >= max_candidates:
            break

    return selected


def run_batch_audit(addresses: List[str]) -> None:
    """
    Lanza contract_deep_audit.py --no-mythril para cada address.
    Usa el mismo intérprete de Python que está ejecutando este script.
    """
    import sys

    python_exe = sys.executable

    for addr in addresses:
        print("\n====================================================")
        print(f"[*] Ejecutando auditoría para {addr}")
        print("====================================================\n")

        cmd = [
            python_exe,
            "contract_deep_audit.py",
            "--address",
            addr,
            "--no-mythril",
        ]
        subprocess.run(cmd, check=False)


def main():
    load_project_env()

    parser = argparse.ArgumentParser(
        description="Filtra candidatos del scanner y ejecuta auditoría profunda sobre los más interesantes."
    )
    parser.add_argument(
        "scanner_json",
        help="Ruta al JSON con la salida del scanner (token_transfer_scanner.py).",
    )
    parser.add_argument(
        "--min-volume",
        type=float,
        default=1000.0,
        help="Volumen mínimo en token para considerar un contrato (por defecto 1000).",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=20,
        help="Número máximo de contratos a auditar (por defecto 20).",
    )
    args = parser.parse_args()

    etherscan_key = os.getenv("ETHERSCAN_API_KEY")
    if not etherscan_key:
        raise RuntimeError("Falta ETHERSCAN_API_KEY en el entorno/.env")

    # Load scanner JSON with a tolerant fallback: some scanner runs write
    # human-readable logs before the actual JSON array/object which causes
    # json.load() to fail. We attempt a few recoveries and provide helpful
    # error messages.
    import re
    import ast

    with open(args.scanner_json, "r", encoding="utf-8") as f:
        raw_text = f.read()

    if not raw_text or not raw_text.strip():
        raise RuntimeError(
            f"Input file '{args.scanner_json}' is empty. Run the scanner to produce JSON output before filtering."
        )

    try:
        scanner_data = json.loads(raw_text)
    except json.JSONDecodeError:
        # Try to extract a JSON array/object embedded after human-readable logs.
        # 1) First try to capture a top-level JSON array like [ { ... } , ... ]
        # Match a JSON array. Allow empty arrays `[]` or arrays of objects.
        arr_match = re.search(r"(\[\s*(?:\{.*?\}.*)?\])", raw_text, re.S)
        if arr_match:
            trimmed = arr_match.group(1)
            try:
                scanner_data = json.loads(trimmed)
                print("[INFO] Loaded JSON array extracted from file.")
            except json.JSONDecodeError as e:
                print(f"[ERROR] Extracted JSON array but json.loads failed: {e}")
                raise
        else:
            # 2) Try to capture a single JSON object
            obj_match = re.search(r"(\{.*?\})", raw_text, re.S)
            if obj_match:
                trimmed = obj_match.group(1)
                try:
                    obj = json.loads(trimmed)
                    # If the scanner produced a single object that contains the list
                    # under a key, try to find it.
                    if isinstance(obj, dict):
                        # heuristics: look for the first list value
                        for v in obj.values():
                            if isinstance(v, list):
                                scanner_data = v
                                print("[INFO] Found list inside extracted JSON object.")
                                break
                        else:
                            # No list inside, fallback to treating the object as a single-item list
                            scanner_data = [obj]
                            print("[INFO] Treated extracted JSON object as single-item list.")
                except json.JSONDecodeError as e:
                    print(f"[ERROR] Extracted JSON object but json.loads failed: {e}")
                    raise
            else:
                # 3) As a last resort, try ast.literal_eval on the whole file (handles single quotes)
                try:
                    scanner_data = ast.literal_eval(raw_text)
                    print("[INFO] Parsed Python literal format via ast.literal_eval.")
                except Exception as e:
                    print(f"[ERROR] Could not parse '{args.scanner_json}' with any strategy: {e}")
                    raise

    # Validate we have a list (scanner output should be an array/list of items)
    if not isinstance(scanner_data, list):
        raise RuntimeError(f"Parsed scanner file but did not find a list at top-level (got {type(scanner_data)}).")

    candidates = pick_interesting_candidates(
        scanner_data=scanner_data,
        etherscan_key=etherscan_key,
        min_volume=args.min_volume,
        max_candidates=args.max,
    )

    if not candidates:
        print("[WARN] No se encontraron candidatos que cumplan los filtros.")
        return

    out_list = [
        {
            "address": addr,
            "volume_token": vol,
            "contract_name": name,
            "bluechip": blue,
        }
        for (addr, vol, name, blue) in candidates
    ]
    out_path = "candidates_for_audit.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_list, f, indent=2)
    print(f"\n[*] Lista de candidatos guardada en {out_path}")

    addrs_only = [addr for (addr, _, _, _) in candidates]
    run_batch_audit(addrs_only)


if __name__ == "__main__":
    main()
