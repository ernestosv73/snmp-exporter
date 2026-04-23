#!/usr/bin/env python3
"""
ping6_test.py
=============
Envía 200 ping6 requests a una dirección IPv6 y devuelve estadísticas
de tiempo (min/avg/max/mdev) para validar la cadencia de paquetes
y correlacionar con las métricas recolectadas por SNMP Exporter y gNMIc.

Uso:
    python3 ping6_test.py
    python3 ping6_test.py --target 2001:db8:20::10 --count 200 --interval 1.0

Dependencias: solo librería estándar de Python (subprocess, statistics, re)

Contexto del estudio:
    - Target: 2001:db8:20::10 (gateway default del nodo que hace ping)
    - 200 pings a 1 paquete/segundo = 200 segundos de tráfico controlado
    - Permite correlacionar ifInUcastPkts / ifOutUcastPkts en SNMP y gNMI
    - El valor esperado de rate()[1m] es exactamente 1 pkts/s
"""

import subprocess
import re
import sys
import time
import statistics
import argparse
from datetime import datetime, timezone


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_TARGET   = "2001:db8:20::10"
DEFAULT_COUNT    = 200
DEFAULT_INTERVAL = 1.0    # segundos entre pings — 1.0 = 1 pkt/s exacto
DEFAULT_TIMEOUT  = 2      # segundos de timeout por ping


# ══════════════════════════════════════════════════════════════════════════════
# PARSER
# ══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Envía ping6 controlado y devuelve estadísticas para "
                    "validación de métricas SNMP/gNMI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--target",   default=DEFAULT_TARGET,
                   help=f"Dirección IPv6 destino (default: {DEFAULT_TARGET})")
    p.add_argument("--count",    type=int, default=DEFAULT_COUNT,
                   help=f"Número de pings (default: {DEFAULT_COUNT})")
    p.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                   help=f"Intervalo entre pings en segundos (default: {DEFAULT_INTERVAL})")
    p.add_argument("--timeout",  type=int, default=DEFAULT_TIMEOUT,
                   help=f"Timeout por ping en segundos (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--verbose",  action="store_true",
                   help="Mostrar cada ping individualmente en tiempo real")
    return p.parse_args()


# ══════════════════════════════════════════════════════════════════════════════
# PING INDIVIDUAL
# ══════════════════════════════════════════════════════════════════════════════

def ping_once(target: str, timeout: int) -> dict:
    """
    Ejecuta un único ping6 y retorna:
        success   : bool
        rtt_ms    : float | None  — RTT en milisegundos
        timestamp : float         — Unix timestamp del envío
        raw       : str           — salida raw del comando
    """
    ts = time.time()
    try:
        result = subprocess.run(
            ["ping6", "-c", "1", "-W", str(timeout), target],
            capture_output=True,
            text=True,
            timeout=timeout + 1,
        )
        output = result.stdout + result.stderr
        # Extraer RTT de línea como: "rtt min/avg/max/mdev = 0.123/0.123/0.123/0.000 ms"
        # o: "64 bytes from ...: icmp_seq=1 ttl=64 time=0.123 ms"
        rtt_match = re.search(r'time[=<]([\d.]+)\s*ms', output)
        rtt = float(rtt_match.group(1)) if rtt_match else None
        success = result.returncode == 0 and rtt is not None
        return {
            "success":   success,
            "rtt_ms":    rtt,
            "timestamp": ts,
            "raw":       output.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "rtt_ms": None, "timestamp": ts, "raw": "TIMEOUT"}
    except FileNotFoundError:
        print("[ERROR] ping6 no encontrado. Verificar que está instalado:")
        print("        sudo apt-get install iputils-ping")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# EJECUCIÓN PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def run_ping_test(target: str, count: int, interval: float,
                  timeout: int, verbose: bool) -> list[dict]:
    """
    Ejecuta `count` pings con `interval` segundos entre cada uno.
    Devuelve la lista de resultados individuales.
    """
    print(f"\n{'═'*60}")
    print(f"  Inicio del test ping6")
    print(f"{'═'*60}")
    print(f"  Target    : {target}")
    print(f"  Pings     : {count}")
    print(f"  Intervalo : {interval}s  →  tasa esperada: {1/interval:.1f} pkts/s")
    print(f"  Timeout   : {timeout}s por ping")
    print(f"  Duración estimada: {count * interval:.0f}s "
          f"({count * interval / 60:.1f} min)")
    print(f"  Inicio    : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'─'*60}\n")

    results = []
    for i in range(1, count + 1):
        t_start = time.time()
        res = ping_once(target, timeout)
        res["seq"] = i
        results.append(res)

        if verbose:
            status = f"RTT={res['rtt_ms']:.3f}ms" if res["success"] else "TIMEOUT/FAIL"
            ts_str = datetime.fromtimestamp(
                res["timestamp"], tz=timezone.utc
            ).strftime("%H:%M:%S.%f")[:-3]
            print(f"  [{i:>3}/{count}] {ts_str} UTC  {status}")
        else:
            # Barra de progreso compacta
            pct = i / count
            bar = "█" * int(pct * 30)
            sent = sum(1 for r in results if r["success"])
            print(f"\r  [{bar:<30}] {i:>3}/{count}  "
                  f"ok={sent}  fail={i-sent}", end="", flush=True)

        # Mantener cadencia exacta compensando el tiempo de ejecución del ping
        elapsed = time.time() - t_start
        sleep_time = max(0.0, interval - elapsed)
        if sleep_time > 0:
            time.sleep(sleep_time)

    if not verbose:
        print()  # nueva línea tras la barra de progreso
    return results


# ══════════════════════════════════════════════════════════════════════════════
# ANÁLISIS ESTADÍSTICO
# ══════════════════════════════════════════════════════════════════════════════

def analyze_results(results: list[dict], interval: float) -> dict:
    """
    Calcula estadísticas compatibles con el formato de ping estándar
    más métricas adicionales relevantes para la validación del estudio.
    """
    total     = len(results)
    successes = [r for r in results if r["success"]]
    failures  = [r for r in results if not r["success"]]
    rtts      = [r["rtt_ms"] for r in successes]

    # Estadísticas RTT
    rtt_min  = min(rtts)          if rtts else None
    rtt_avg  = statistics.mean(rtts)    if rtts else None
    rtt_max  = max(rtts)          if rtts else None
    rtt_mdev = statistics.stdev(rtts)   if len(rtts) > 1 else 0.0

    # Análisis de cadencia real (inter-arrival time entre pings enviados)
    timestamps = [r["timestamp"] for r in results]
    iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    iat_avg  = statistics.mean(iats)  if iats else interval
    iat_min  = min(iats)        if iats else interval
    iat_max  = max(iats)        if iats else interval
    iat_mdev = statistics.stdev(iats) if len(iats) > 1 else 0.0

    # Duración real del test
    duration = results[-1]["timestamp"] - results[0]["timestamp"] if len(results) > 1 else 0
    actual_rate = (len(successes) / duration) if duration > 0 else 0

    # Identificar posibles pérdidas consecutivas (relevante para SNMP walk timing)
    consecutive_fails = 0
    max_consecutive   = 0
    for r in results:
        if not r["success"]:
            consecutive_fails += 1
            max_consecutive = max(max_consecutive, consecutive_fails)
        else:
            consecutive_fails = 0

    return {
        "total":              total,
        "transmitted":        total,
        "received":           len(successes),
        "failed":             len(failures),
        "packet_loss_pct":    round((len(failures) / total) * 100, 1),
        "rtt_min_ms":         round(rtt_min,  3) if rtt_min  is not None else None,
        "rtt_avg_ms":         round(rtt_avg,  3) if rtt_avg  is not None else None,
        "rtt_max_ms":         round(rtt_max,  3) if rtt_max  is not None else None,
        "rtt_mdev_ms":        round(rtt_mdev, 3),
        "iat_avg_s":          round(iat_avg,  4),
        "iat_min_s":          round(iat_min,  4),
        "iat_max_s":          round(iat_max,  4),
        "iat_mdev_s":         round(iat_mdev, 4),
        "test_duration_s":    round(duration, 2),
        "actual_rate_pps":    round(actual_rate, 4),
        "expected_rate_pps":  round(1 / interval, 4),
        "max_consecutive_fail": max_consecutive,
    }


# ══════════════════════════════════════════════════════════════════════════════
# INFORME
# ══════════════════════════════════════════════════════════════════════════════

def print_report(stats: dict, target: str, interval: float):
    """Imprime el informe en formato compatible con el estudio comparativo."""

    sep = "═" * 60

    print(f"\n{sep}")
    print(f"  RESULTADOS — ping6 a {target}")
    print(sep)

    # ── Bloque 1: resumen estilo ping estándar ──────────────────────────────
    print(f"\n  {stats['transmitted']} packets transmitted, "
          f"{stats['received']} received, "
          f"{stats['packet_loss_pct']}% packet loss, "
          f"time {stats['test_duration_s']}s")

    if stats['rtt_min_ms'] is not None:
        print(f"  rtt min/avg/max/mdev = "
              f"{stats['rtt_min_ms']:.3f}/"
              f"{stats['rtt_avg_ms']:.3f}/"
              f"{stats['rtt_max_ms']:.3f}/"
              f"{stats['rtt_mdev_ms']:.3f} ms")
    else:
        print("  rtt min/avg/max/mdev = N/A (sin respuestas)")

    # ── Bloque 2: cadencia de envío ─────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"  Cadencia de envío (inter-arrival time)")
    print(f"{'─'*60}")
    print(f"  Intervalo configurado : {interval:.3f}s")
    print(f"  IAT avg / min / max   : {stats['iat_avg_s']:.4f}s / "
          f"{stats['iat_min_s']:.4f}s / {stats['iat_max_s']:.4f}s")
    print(f"  IAT mdev              : {stats['iat_mdev_s']:.4f}s  "
          f"({'OK — cadencia estable' if stats['iat_mdev_s'] < 0.01 else 'ATENCIÓN — jitter de envío'})")

    # ── Bloque 3: tasa real vs esperada ─────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"  Tasa de paquetes — validación del estudio")
    print(f"{'─'*60}")
    print(f"  Tasa esperada (1/interval)  : {stats['expected_rate_pps']:.4f} pkts/s")
    print(f"  Tasa real medida            : {stats['actual_rate_pps']:.4f} pkts/s")
    delta_pct = abs(stats['actual_rate_pps'] - stats['expected_rate_pps']) \
                / stats['expected_rate_pps'] * 100
    print(f"  Desviación                  : {delta_pct:.2f}%  "
          f"({'aceptable ≤1%' if delta_pct <= 1.0 else 'revisar'})")

    # ── Bloque 4: interpretación para el estudio ───────────────────────────
    print(f"\n{'─'*60}")
    print(f"  Interpretación para el análisis comparativo SNMP vs gNMI")
    print(f"{'─'*60}")

    # SNMP scrape_interval y sincronía
    for scrape_s in [5, 15, 30]:
        pkts_per_scrape = interval * scrape_s  # paquetes esperados entre scrapes
        # Variabilidad por asincronía: ±1 paquete por ciclo
        rate_low  = (pkts_per_scrape - 1) / scrape_s
        rate_high = (pkts_per_scrape + 1) / scrape_s
        print(f"\n  Con scrape_interval={scrape_s}s:")
        print(f"    Pkts esperados entre scrapes : {pkts_per_scrape:.0f}")
        print(f"    Variación por asincronía (±1 pkt):")
        print(f"      rate() mín estimado        : {rate_low:.3f} pkts/s")
        print(f"      rate() máx estimado        : {rate_high:.3f} pkts/s")
        print(f"      Rango de sierra SNMP       : ±{((rate_high-rate_low)/2):.3f} pkts/s")
        print(f"    gNMI con sample={scrape_s}s    : 1.000 pkts/s (timestamp hw exacto)")

    # Pérdidas
    if stats['failed'] > 0:
        print(f"\n  ATENCIÓN: {stats['failed']} pings fallidos "
              f"(max consecutivos: {stats['max_consecutive_fail']})")
        print(f"  Esto puede afectar los contadores ifIn/OutUcastPkts en el dispositivo.")
        print(f"  Verificar conectividad y ajustar --timeout si es necesario.")
    else:
        print(f"\n  Sin pérdidas — los 200 paquetes fueron confirmados.")
        print(f"  ifInUcastPkts y ifOutUcastPkts en el dispositivo")
        print(f"  deberían haber incrementado en exactamente {stats['received']} unidades.")

    print(f"\n{'═'*60}")
    print(f"  Fin del test: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'═'*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    args    = parse_args()
    results = run_ping_test(
        target   = args.target,
        count    = args.count,
        interval = args.interval,
        timeout  = args.timeout,
        verbose  = args.verbose,
    )
    stats = analyze_results(results, args.interval)
    print_report(stats, args.target, args.interval)


if __name__ == "__main__":
    main()
