#!/usr/bin/env python3
"""
flood_attack_test.py
====================
Ejecuta atk6-flood_advertise6 durante una duración configurable para
analizar la capacidad de detección de ráfagas de tráfico (flooding)
en los escenarios SNMP Exporter y gNMIc del estudio comparativo.

Tipo de ataque:
    atk6-flood_advertise6 genera ICMPv6 Neighbor Advertisement masivos con
    MACs e IPs IPv6 aleatorias. El tráfico generado es MULTICAST (destino
    ff02::1 y solicited-node ff02::1:ffXX:XXXX), por lo que las métricas
    relevantes NO son ifInUcastPkts sino:

    SNMP (IF-MIB RFC 2863):
        ifHCInMulticastPkts  → contador principal del flooding multicast
        ifInErrors           → paquetes malformados rechazados por el dispositivo
        ifInDiscards         → paquetes descartados por overflow de buffer

    gNMIc (YANG Nokia SRL):
        in-multicast-packets → equivalente a ifHCInMulticastPkts
        in-error-packets     → equivalente a ifInErrors
        in-discarded-packets → equivalente a ifInDiscards

    Firma del ataque: pico en ifHCInMulticastPkts + incremento simultáneo
    en ifInDiscards cuando la tasa supera la capacidad del buffer.

Uso:
    sudo python3 flood_attack_test.py
    sudo python3 flood_attack_test.py --iface eth1 --duration 30
    sudo python3 flood_attack_test.py --duration 60 --repeat 4 --pause 30

Requiere:
    - THC IPv6 instalado: apt-get install thc-ipv6
    - Permisos root (sudo)

Contexto del estudio:
    Duración del ataque vs scrape_interval/sample_interval = 5s
    Duraciones de prueba recomendadas:
        5s  → < 1 scrape — punto ciego con rate()[1m], visible con irate()
        10s → 2 scrapes  — marginal con rate()[1m], detectable con irate()[1m]
        30s → 6 scrapes  — diferencia morfológica notable entre operadores
        60s → 12 scrapes — claramente visible con rate()[1m] e irate()[1m]
    Conclusión esperada:
        irate() detecta ráfagas que rate() oculta, mayor sensibilidad al ruido
        gNMI in-bps equivalente a irate() sin depender del operador del colector
        La firma multicast distingue el flooding de tráfico unicast legítimo
"""

import subprocess
import signal
import sys
import time
import os
import argparse
from datetime import datetime, timezone


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN — modificar según el escenario de prueba
# ══════════════════════════════════════════════════════════════════════════════

# Interfaz de red sobre la que se ejecuta el ataque
INTERFACE = "eth1"

# Duración del ataque en segundos — VARIABLE PRINCIPAL DEL EXPERIMENTO
# Valores recomendados para el estudio: 5, 10, 30, 60
ATTACK_DURATION_SECONDS = 5

# Número de repeticiones del ataque (para pruebas comparativas)
REPEAT_COUNT = 1

# Pausa entre repeticiones en segundos
PAUSE_BETWEEN_ATTACKS = 15

# Comando THC IPv6 a ejecutar
# atk6-flood_advertise6: genera ICMPv6 Neighbor Advertisement masivos
# simula un flood de anuncios de vecinos IPv6
THC_COMMAND = "atk6-flood_advertise6"


# ══════════════════════════════════════════════════════════════════════════════
# UTILIDADES
# ══════════════════════════════════════════════════════════════════════════════

def timestamp_utc() -> str:
    """Retorna timestamp UTC formateado para logs."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def check_requirements(iface: str):
    """Verifica que el entorno está listo para ejecutar el ataque."""
    errors = []

    # Verificar permisos root
    if os.geteuid() != 0:
        errors.append("Se requieren permisos root. Ejecutar con: sudo python3 flood_attack_test.py")

    # Verificar que THC IPv6 está instalado
    result = subprocess.run(
        ["which", THC_COMMAND],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        errors.append(
            f"THC IPv6 no encontrado ({THC_COMMAND}).\n"
            "        Instalar con: sudo apt-get install thc-ipv6"
        )

    # Verificar que la interfaz existe
    result = subprocess.run(
        ["ip", "link", "show", iface],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        errors.append(
            f"Interfaz '{iface}' no encontrada.\n"
            f"        Interfaces disponibles: use 'ip link show' para listar"
        )

    if errors:
        print("\n[ERROR] Verificación de requisitos fallida:")
        for e in errors:
            print(f"  • {e}")
        sys.exit(1)

    print(f"  [OK] Permisos root verificados")
    print(f"  [OK] {THC_COMMAND} disponible")
    print(f"  [OK] Interfaz {iface} disponible")


def print_study_context(duration: int, repeat: int, pause: int,
                        iface: str, scrape_interval: int = 5):
    """Imprime el contexto del experimento para el estudio comparativo."""
    print(f"\n{'─'*60}")
    print(f"  Contexto del experimento — Detección de flooding IPv6")
    print(f"{'─'*60}")
    print(f"  Duración del ataque    : {duration}s")
    print(f"  scrape_interval (SNMP) : {scrape_interval}s")
    print(f"  sample_interval (gNMI) : {scrape_interval}s")
    print(f"  Muestras SNMP durante  : {duration / scrape_interval:.1f} scrapes")
    print(f"  Muestras gNMI durante  : {duration / scrape_interval:.1f} samples")

    # Análisis de detectabilidad esperada
    ratio = duration / scrape_interval
    print(f"\n  Detectabilidad esperada (rate()[1m] = ventana 12 muestras):")
    if ratio < 1:
        print(f"  [SNMP  rate()[1m]]    BAJA  — {duration}s < 1 scrape → punto ciego")
        print(f"  [SNMP  irate()[1m]]   MEDIA — visible si el scrape coincide con la ráfaga")
        print(f"  [gNMI  rate()[1m]]    BAJA  — mismo efecto de suavizado que SNMP")
        print(f"  [gNMI  irate()[1m]]   MEDIA — mejor precisión por timestamp hardware")
        print(f"  [gNMI  on_change]     ALTA  — detecta el cambio en el instante")
        print(f"  [gNMI  in-bps]        ALTA  — tasa instantánea del dispositivo")
    elif ratio < 2:
        print(f"  [SNMP  rate()[1m]]    BAJA  — pico diluido en ventana de 60s")
        print(f"  [SNMP  irate()[1m]]   ALTA  — pico visible en {ratio:.0f}-2 muestras")
        print(f"  [gNMI  rate()[1m]]    MEDIA — flancos más precisos que SNMP")
        print(f"  [gNMI  irate()[1m]]   ALTA  — plateau estable en las muestras del ataque")
        print(f"  [gNMI  in-bps]        ALTA  — máxima precisión, sin operador necesario")
    elif ratio < 6:
        print(f"  [SNMP  rate()[1m]]    MEDIA — forma triangular, pico subestimado")
        print(f"  [SNMP  irate()[1m]]   ALTA  — forma más rectangular, pico real")
        print(f"  [gNMI  rate()[1m]]    ALTA  — plateau más estable que SNMP")
        print(f"  [gNMI  irate()[1m]]   ALTA  — representación precisa")
        print(f"  [gNMI  in-bps]        ALTA  — referencia exacta del dispositivo")
    else:
        print(f"  [SNMP  rate()[1m]]    ALTA  — visible pero con suavizado triangular")
        print(f"  [SNMP  irate()[1m]]   ALTA  — forma rectangular, pico preciso")
        print(f"  [gNMI  rate()[1m]]    ALTA  — representación estable")
        print(f"  [gNMI  irate()[1m]]   ALTA  — representación rectangular precisa")
        print(f"  [gNMI  in-bps]        ALTA  — máxima fidelidad")
    print(f"{'─'*60}")


# ══════════════════════════════════════════════════════════════════════════════
# EJECUCIÓN DEL ATAQUE
# ══════════════════════════════════════════════════════════════════════════════

def run_attack(iface: str, duration: int, run_number: int, total_runs: int) -> dict:
    """
    Ejecuta atk6-flood_advertise6 durante `duration` segundos.
    Retorna un dict con los metadatos de la ejecución.
    """
    cmd = [THC_COMMAND, iface]

    print(f"\n{'═'*60}")
    print(f"  Ataque {run_number}/{total_runs} — {THC_COMMAND} {iface}")
    print(f"  Duración configurada: {duration}s")
    print(f"  Inicio: {timestamp_utc()}")
    print(f"{'═'*60}")
    print(f"  [*] Lanzando ataque... (Ctrl+C para interrumpir)\n")

    process  = None
    t_start  = time.time()
    ts_start = timestamp_utc()

    try:
        # Lanzar el proceso en background
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,   # grupo de procesos independiente
        )

        # Barra de progreso durante el ataque
        for elapsed in range(duration):
            remaining = duration - elapsed
            bar       = "█" * int((elapsed / duration) * 30)
            print(f"\r  [{bar:<30}] {remaining:3d}s restantes  "
                  f"PID={process.pid}", end="", flush=True)
            time.sleep(1)
            # Verificar que el proceso sigue corriendo
            if process.poll() is not None:
                print(f"\n  [!] El proceso terminó antes de lo esperado "
                      f"(código: {process.returncode})")
                break

        print(f"\r  [{'█'*30}] Completado.                           ")

    except KeyboardInterrupt:
        print(f"\n  [!] Interrumpido manualmente por el usuario")

    finally:
        # Asegurar terminación del proceso
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

    print(f"\n  Fin: {ts_end}")
    print(f"  Duración real: {real_dur}s (configurada: {duration}s)")

    return {
        "run":           run_number,
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

def print_report(runs: list[dict], scrape_interval: int = 5):
    """Imprime el resumen para correlación con Grafana."""
    print(f"\n{'═'*60}")
    print(f"  RESUMEN DEL EXPERIMENTO")
    print(f"{'═'*60}")
    print(f"  Total de ataques ejecutados: {len(runs)}\n")

    for r in runs:
        print(f"  Ataque {r['run']}:")
        print(f"    Inicio   : {r['ts_start']}")
        print(f"    Fin      : {r['ts_end']}")
        print(f"    Duración : {r['duration_real']}s (cfg: {r['duration_cfg']}s)")
        print(f"    Unix ts  : {r['t_start_unix']} → {r['t_end_unix']}")
        print()

    print(f"{'─'*60}")
    print(f"  Uso en Grafana para correlación:")
    print(f"  Añadir anotaciones manuales en los timestamps de inicio/fin")
    print(f"  o usar la función 'Add annotation' de Grafana con los valores Unix.")
    print(f"\n  PromQL sugerido para visualizar el impacto:")
    print(f"")
    print(f"  Métricas objetivo para flooding IPv6 multicast:")
    print(f"  (atk6-flood_advertise6 genera tráfico MULTICAST, no unicast)")
    print(f"")
    print(f"  [1] ifHCInMulticastPkts / in-multicast-packets — contador principal:")
    print(f"    irate(ifHCInMulticastPkts{{ifDescr='eth1'}}[1m])           ← SNMP irate")
    print(f"    rate(ifHCInMulticastPkts{{ifDescr='eth1'}}[1m])            ← SNMP rate")
    print(f"    irate(in_multicast_packets{{interface='eth1'}}[1m])        ← gNMI irate")
    print(f"    rate(in_multicast_packets{{interface='eth1'}}[1m])         ← gNMI rate")
    print(f"")
    print(f"  [2] ifInErrors / in-error-packets — paquetes malformados:")
    print(f"    irate(ifInErrors{{ifDescr='eth1'}}[1m])                    ← SNMP irate")
    print(f"    irate(in_error_packets{{interface='eth1'}}[1m])            ← gNMI irate")
    print(f"")
    print(f"  [3] ifInDiscards / in-discarded-packets — overflow de buffer:")
    print(f"    irate(ifInDiscards{{ifDescr='eth1'}}[1m])                  ← SNMP irate")
    print(f"    irate(in_discarded_packets{{interface='eth1'}}[1m])        ← gNMI irate")
    print(f"")
    print(f"  Firma del ataque (correlación de las tres métricas):")
    print(f"    pico en multicast + incremento en discards = flooding activo")
    print(f"    pico en multicast + incremento en errors   = paquetes malformados")
    print(f"")
    print(f"  Trade-off operadores:")
    print(f"    irate() → 2 muestras, detecta ráfagas de 5s, más ruido en baseline")
    print(f"    rate()  → 12 muestras, diluye ráfagas cortas (8% si dura 5s en 60s)")
    print(f"{'═'*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="Ejecuta flood_advertise6 con duración configurable "
                    "para el estudio comparativo SNMP vs gNMI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--iface",    default=INTERFACE,
                   help=f"Interfaz de red (default: {INTERFACE})")
    p.add_argument("--duration", type=int, default=ATTACK_DURATION_SECONDS,
                   help=f"Duración del ataque en segundos (default: {ATTACK_DURATION_SECONDS})")
    p.add_argument("--repeat",   type=int, default=REPEAT_COUNT,
                   help=f"Número de repeticiones (default: {REPEAT_COUNT})")
    p.add_argument("--pause",    type=int, default=PAUSE_BETWEEN_ATTACKS,
                   help=f"Pausa entre ataques en segundos (default: {PAUSE_BETWEEN_ATTACKS})")
    p.add_argument("--scrape-interval", type=int, default=5,
                   help="scrape_interval / sample_interval configurado (default: 5)")
    return p.parse_args()


def main():
    args = parse_args()

    print(f"\n{'═'*60}")
    print(f"  flood_attack_test.py — Estudio comparativo SNMP vs gNMI")
    print(f"{'═'*60}")

    # Verificar entorno
    print(f"\n  Verificando requisitos...")
    check_requirements(args.iface)

    # Mostrar contexto del estudio
    print_study_context(
        duration        = args.duration,
        repeat          = args.repeat,
        pause           = args.pause,
        iface           = args.iface,
        scrape_interval = args.scrape_interval,
    )

    # Confirmación antes de ejecutar
    print(f"\n  Se ejecutarán {args.repeat} ataque(s) de {args.duration}s "
          f"sobre {args.iface}.")
    confirm = input("  ¿Continuar? [s/N]: ").strip().lower()
    if confirm not in ("s", "si", "sí", "y", "yes"):
        print("  Cancelado.")
        sys.exit(0)

    # Ejecutar ataques
    runs = []
    for i in range(1, args.repeat + 1):
        result = run_attack(
            iface      = args.iface,
            duration   = args.duration,
            run_number = i,
            total_runs = args.repeat,
        )
        runs.append(result)

        # Pausa entre ataques (excepto el último)
        if i < args.repeat:
            print(f"\n  Pausa de {args.pause}s antes del siguiente ataque...")
            for remaining in range(args.pause, 0, -1):
                print(f"\r  Próximo ataque en {remaining:3d}s...", end="", flush=True)
                time.sleep(1)
            print()

    # Informe final
    print_report(runs, args.scrape_interval)


if __name__ == "__main__":
    main()
