#!/bin/bash

# Copyright 2026 University of California, Riverside and National Yang Ming Chiao Tung University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# ---------------------------------------------------------------------------
# Test bandwidth configuration.
#
# By default, the script calculates test bandwidth points from the configured
# UE/QoS rates. Values are Mbps. For the current validation profile:
#   UE AMBR = 10 Mbps, QoS GBR = 2 Mbps, QoS MBR = 5 Mbps
#
# This generates:
#   QoS sweep:       3 4 5 6 8 10
#   non-QoS sweep:   7.5 10 12.5 15
#   two-flow pairs:  3:3 3:10 5:10 6:6 10:10 10:5
#
# Set AUTO_CALCULATE_RATES=0 to use the manual lists below instead.
# ---------------------------------------------------------------------------
AUTO_CALCULATE_RATES=${AUTO_CALCULATE_RATES:-1}
UE_AMBR_MBPS=${UE_AMBR_MBPS:-10}
QOS_GBR_MBPS=${QOS_GBR_MBPS:-2}
QOS_MBR_MBPS=${QOS_MBR_MBPS:-5}

QOS_TEST_RATES_MBPS=(3 4 5 6 8 10)
NON_QOS_TEST_RATES_MBPS=(6 8 10 12)
TWO_FLOW_TEST_PAIRS_MBPS=("3:3" "3:7" "5:5" "6:6" "8:8" "5:8" "8:5")

SERVER_IP=${SERVER_IP:-10.60.0.1}
QOS_BIND_IP=${QOS_BIND_IP:-192.168.3.2}
NON_QOS_BIND_IP=${NON_QOS_BIND_IP:-192.168.3.3}
QOS_PORT=${QOS_PORT:-5201}
QOS_SECOND_PORT=${QOS_SECOND_PORT:-5203}
NON_QOS_PORT=${NON_QOS_PORT:-5202}
SHARED_QER_RATE_MBPS=${SHARED_QER_RATE_MBPS:-}
DURATION=${DURATION:-30}
OMIT=${OMIT:-3}
PAUSE=${PAUSE:-2}
LOG_ROOT=${LOG_ROOT:-"iperf log/validation"}
LIVE_OUTPUT=${LIVE_OUTPUT:-0}

is_number() {
    [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

fmt_mbps() {
    awk -v v="$1" 'BEGIN {
        if (v < 0.0005 && v > -0.0005)
            v = 0;
        s = sprintf("%.3f", v);
        sub(/\.?0+$/, "", s);
        print s;
    }'
}

mode=${1:-both}
if [ "$#" -eq 3 ] && is_number "$1" && is_number "$2" && is_number "$3"; then
    mode=all
    UE_AMBR_MBPS=$1
    QOS_GBR_MBPS=$2
    QOS_MBR_MBPS=$3
elif [ "$#" -ge 4 ]; then
    if [ "$#" -gt 4 ]; then
        echo "Too many arguments." >&2
        exit 2
    fi
    mode=$1
    UE_AMBR_MBPS=$2
    QOS_GBR_MBPS=$3
    QOS_MBR_MBPS=$4
elif [ "$#" -eq 2 ]; then
    echo "Expected either [mode], [ambr gbr mbr], or [mode ambr gbr mbr]." >&2
    exit 2
elif [ "$#" -eq 3 ]; then
    echo "For three arguments, use [ambr gbr mbr], for example: $0 10 2 5." >&2
    exit 2
fi

SHARED_QER_RATE_MBPS=${SHARED_QER_RATE_MBPS:-${QOS_MBR_MBPS}}

unique_positive_list() {
    local out=""
    local raw
    local value

    for raw in "$@"; do
        value=$(fmt_mbps "${raw}")
        if awk -v v="${value}" 'BEGIN { exit !(v > 0) }'; then
            case " ${out} " in
                *" ${value} "*) ;;
                *) out="${out:+${out} }${value}" ;;
            esac
        fi
    done

    echo "${out}"
}

append_pair() {
    local current=$1
    local qos_raw=$2
    local non_qos_raw=$3
    local qos_rate
    local non_qos_rate
    local pair

    qos_rate=$(fmt_mbps "${qos_raw}")
    non_qos_rate=$(fmt_mbps "${non_qos_raw}")
    if ! awk -v q="${qos_rate}" -v n="${non_qos_rate}" \
        'BEGIN { exit !(q > 0 && n > 0) }'; then
        echo "${current}"
        return
    fi

    pair="${qos_rate}:${non_qos_rate}"
    case " ${current} " in
        *" ${pair} "*) echo "${current}" ;;
        *) echo "${current:+${current} }${pair}" ;;
    esac
}

generate_bandwidth_plan() {
    local ambr=$1
    local mbr=$3
    local qos_cap
    local non_qos_cap
    local clean_qos
    local two_flow=""

    qos_cap=$(awk -v m="${mbr}" 'BEGIN { printf "%.6f", m }')
    non_qos_cap=$(awk -v a="${ambr}" 'BEGIN { printf "%.6f", a }')
    clean_qos=$(awk -v q="${qos_cap}" 'BEGIN { printf "%.6f", q * 0.6 }')

    GENERATED_QOS_RATES=$(unique_positive_list \
        "$(awk -v q="${qos_cap}" 'BEGIN { printf "%.6f", q * 0.6 }')" \
        "$(awk -v q="${qos_cap}" 'BEGIN { printf "%.6f", q * 0.8 }')" \
        "${qos_cap}" \
        "$(awk -v q="${qos_cap}" 'BEGIN { printf "%.6f", q * 1.2 }')" \
        "$(awk -v q="${qos_cap}" 'BEGIN { printf "%.6f", q * 1.6 }')" \
        "$(awk -v q="${qos_cap}" 'BEGIN { printf "%.6f", q * 2.0 }')")

    GENERATED_NON_QOS_RATES=$(unique_positive_list \
        "$(awk -v n="${non_qos_cap}" 'BEGIN { printf "%.6f", n * 0.75 }')" \
        "${non_qos_cap}" \
        "$(awk -v n="${non_qos_cap}" 'BEGIN { printf "%.6f", n * 1.25 }')" \
        "$(awk -v n="${non_qos_cap}" 'BEGIN { printf "%.6f", n * 1.5 }')")

    two_flow=$(append_pair "${two_flow}" "${clean_qos}" "${clean_qos}")
    two_flow=$(append_pair "${two_flow}" "${clean_qos}" "${non_qos_cap}")
    two_flow=$(append_pair "${two_flow}" "${qos_cap}" "${non_qos_cap}")
    two_flow=$(append_pair "${two_flow}" \
        "$(awk -v q="${qos_cap}" 'BEGIN { printf "%.6f", q * 1.2 }')" \
        "$(awk -v q="${qos_cap}" 'BEGIN { printf "%.6f", q * 1.2 }')")
    two_flow=$(append_pair "${two_flow}" "${non_qos_cap}" "${non_qos_cap}")
    two_flow=$(append_pair "${two_flow}" "${qos_cap}" "${non_qos_cap}")
    two_flow=$(append_pair "${two_flow}" "${non_qos_cap}" "${qos_cap}")
    GENERATED_TWO_FLOW_PAIRS="${two_flow}"
    GENERATED_QOS_CAP=$(fmt_mbps "${qos_cap}")
    GENERATED_NON_QOS_CAP=$(fmt_mbps "${non_qos_cap}")
}

GENERATED_QOS_RATES=""
GENERATED_NON_QOS_RATES=""
GENERATED_TWO_FLOW_PAIRS=""
GENERATED_QOS_CAP=""
GENERATED_NON_QOS_CAP=""

if [ "${AUTO_CALCULATE_RATES}" = "1" ]; then
    generate_bandwidth_plan "${UE_AMBR_MBPS}" "${QOS_GBR_MBPS}" "${QOS_MBR_MBPS}"
    QOS_RATES=${QOS_RATES:-"${GENERATED_QOS_RATES}"}
    NON_QOS_RATES=${NON_QOS_RATES:-"${GENERATED_NON_QOS_RATES}"}
    TWO_FLOW_PAIRS=${TWO_FLOW_PAIRS:-"${GENERATED_TWO_FLOW_PAIRS}"}
else
    QOS_RATES=${QOS_RATES:-"${QOS_TEST_RATES_MBPS[*]}"}
    NON_QOS_RATES=${NON_QOS_RATES:-"${NON_QOS_TEST_RATES_MBPS[*]}"}
    TWO_FLOW_PAIRS=${TWO_FLOW_PAIRS:-"${TWO_FLOW_TEST_PAIRS_MBPS[*]}"}
fi

timestamp=$(date -u +%Y%m%d-%H%M%S)
log_dir="${LOG_ROOT}/${timestamp}"
mkdir -p "${log_dir}"

commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

usage() {
    cat <<EOF
Usage:
  $0 [qos|non-qos|both|two-flow|shared-qer|all]
  $0 [ambr_mbps gbr_mbps mbr_mbps]
  $0 [qos|non-qos|both|two-flow|shared-qer|all] [ambr_mbps gbr_mbps mbr_mbps]

Environment overrides:
  SERVER_IP        UE iperf3 server IP. Default: ${SERVER_IP}
  QOS_BIND_IP      DN source IP for QoS flow. Default: ${QOS_BIND_IP}
  NON_QOS_BIND_IP  DN source IP for default/non-QoS flow. Default: ${NON_QOS_BIND_IP}
  QOS_PORT         QoS iperf3 server port. Default: ${QOS_PORT}
  QOS_SECOND_PORT  Second QoS server port for shared-QER tests. Default: ${QOS_SECOND_PORT}
  SHARED_QER_RATE_MBPS
                   Offered rate for each shared-QER 5-tuple. Default: ${SHARED_QER_RATE_MBPS}
  NON_QOS_PORT     Default/non-QoS iperf3 server port. Default: ${NON_QOS_PORT}
  DURATION         Seconds per offered rate. Default: ${DURATION}
  OMIT             Initial seconds omitted by iperf3. Default: ${OMIT}
  PAUSE            Seconds between runs. Default: ${PAUSE}
  AUTO_CALCULATE_RATES
                   Generate bandwidth points from AMBR/GBR/MBR. Default: ${AUTO_CALCULATE_RATES}
  UE_AMBR_MBPS     UE/session AMBR used for auto generation. Default: ${UE_AMBR_MBPS}
  QOS_GBR_MBPS     QoS GBR used for auto generation. Default: ${QOS_GBR_MBPS}
  QOS_MBR_MBPS     QoS MBR used for auto generation. Default: ${QOS_MBR_MBPS}
  QOS_RATES        QoS offered Mbps list. Default: ${QOS_RATES}
  NON_QOS_RATES    Default/non-QoS offered Mbps list. Default: ${NON_QOS_RATES}
  TWO_FLOW_PAIRS   Concurrent QoS:non-QoS Mbps pairs. Default: ${TWO_FLOW_PAIRS}
  LOG_ROOT         Output root directory. Default: ${LOG_ROOT}
  LIVE_OUTPUT      Print iperf3 output while logging. Default: ${LIVE_OUTPUT}

To change the persistent automatic plan, edit UE_AMBR_MBPS, QOS_GBR_MBPS, and
QOS_MBR_MBPS near the top of this script. Set AUTO_CALCULATE_RATES=0 to use the
manual QOS_TEST_RATES_MBPS, NON_QOS_TEST_RATES_MBPS, and
TWO_FLOW_TEST_PAIRS_MBPS lists.
EOF
}

progress() {
    echo "[$(date -u +%H:%M:%S)] $*"
}

run_logged() {
    local log_file=$1
    shift

    if [ "${LIVE_OUTPUT}" = "1" ]; then
        set +e
        "$@" 2>&1 | tee -a "${log_file}"
        local status=${PIPESTATUS[0]}
        set -e
        return "${status}"
    fi

    "$@" >> "${log_file}" 2>&1
}

run_sweep() {
    local label=$1
    local bind_ip=$2
    local port=$3
    local rates=$4
    local log_file="${log_dir}/dn-${label}-sweep-${timestamp}.log"

    progress "Starting ${label} sweep; log: ${log_file}"

    {
        echo "# UPF-U shaper validation sweep"
        echo "# date_utc: $(date -u)"
        echo "# git_commit: ${commit}"
        echo "# server_ip: ${SERVER_IP}"
        echo "# bind_ip: ${bind_ip}"
        echo "# port: ${port}"
        echo "# duration: ${DURATION}"
        echo "# omit: ${OMIT}"
        echo "# auto_calculate_rates: ${AUTO_CALCULATE_RATES}"
        echo "# ue_ambr_mbps: ${UE_AMBR_MBPS}"
        echo "# qos_gbr_mbps: ${QOS_GBR_MBPS}"
        echo "# qos_mbr_mbps: ${QOS_MBR_MBPS}"
        echo "# qos_cap_mbps: ${GENERATED_QOS_CAP:-manual}"
        echo "# non_qos_cap_mbps: ${GENERATED_NON_QOS_CAP:-manual}"
        echo "# rates_mbps: ${rates}"
        echo
    } > "${log_file}"

    for rate in ${rates}; do
        {
            echo "===== ${label} sweep: ${rate} Mbps, $(date -u) ====="
            echo "Command: iperf3 -c ${SERVER_IP} -B ${bind_ip} -p ${port} -u -b ${rate}M -t ${DURATION} -O ${OMIT} -i 1"
        } >> "${log_file}"

        progress "Running ${label} ${rate} Mbps for ${DURATION}s"
        if ! run_logged "${log_file}" iperf3 -c "${SERVER_IP}" -B "${bind_ip}" -p "${port}" -u -b "${rate}M" -t "${DURATION}" -O "${OMIT}" -i 1; then
            echo "iperf3 failed for ${label} ${rate} Mbps" >> "${log_file}"
            progress "FAILED ${label} ${rate} Mbps"
        else
            progress "Finished ${label} ${rate} Mbps"
        fi

        echo >> "${log_file}"
        sleep "${PAUSE}"
    done

    progress "Completed ${label} sweep"
    echo "${log_file}"
}

run_two_flow() {
    local summary_file="${log_dir}/dn-twoflow-summary-${timestamp}.log"

    progress "Starting two-flow sharing test; summary: ${summary_file}"

    {
        echo "# UPF-U shaper concurrent two-flow validation"
        echo "# date_utc: $(date -u)"
        echo "# git_commit: ${commit}"
        echo "# server_ip: ${SERVER_IP}"
        echo "# qos_bind_ip: ${QOS_BIND_IP}"
        echo "# non_qos_bind_ip: ${NON_QOS_BIND_IP}"
        echo "# qos_port: ${QOS_PORT}"
        echo "# non_qos_port: ${NON_QOS_PORT}"
        echo "# duration: ${DURATION}"
        echo "# omit: ${OMIT}"
        echo "# auto_calculate_rates: ${AUTO_CALCULATE_RATES}"
        echo "# ue_ambr_mbps: ${UE_AMBR_MBPS}"
        echo "# qos_gbr_mbps: ${QOS_GBR_MBPS}"
        echo "# qos_mbr_mbps: ${QOS_MBR_MBPS}"
        echo "# qos_cap_mbps: ${GENERATED_QOS_CAP:-manual}"
        echo "# non_qos_cap_mbps: ${GENERATED_NON_QOS_CAP:-manual}"
        echo "# pairs_mbps: ${TWO_FLOW_PAIRS}"
        echo
    } > "${summary_file}"

    for pair in ${TWO_FLOW_PAIRS}; do
        local qos_rate=${pair%%:*}
        local non_qos_rate=${pair#*:}
        local pair_tag="qos-${qos_rate}m-nonqos-${non_qos_rate}m"
        local qos_log="${log_dir}/dn-twoflow-${pair_tag}-qos-${timestamp}.log"
        local non_qos_log="${log_dir}/dn-twoflow-${pair_tag}-non-qos-${timestamp}.log"
        local qos_status=0
        local non_qos_status=0

        {
            echo "===== two-flow pair: QoS ${qos_rate} Mbps + non-QoS ${non_qos_rate} Mbps, $(date -u) ====="
            echo "QoS log: ${qos_log}"
            echo "non-QoS log: ${non_qos_log}"
            echo "QoS command: iperf3 -c ${SERVER_IP} -B ${QOS_BIND_IP} -p ${QOS_PORT} -u -b ${qos_rate}M -t ${DURATION} -O ${OMIT} -i 1"
            echo "non-QoS command: iperf3 -c ${SERVER_IP} -B ${NON_QOS_BIND_IP} -p ${NON_QOS_PORT} -u -b ${non_qos_rate}M -t ${DURATION} -O ${OMIT} -i 1"
        } >> "${summary_file}"

        progress "Running two-flow QoS ${qos_rate} Mbps + non-QoS ${non_qos_rate} Mbps for ${DURATION}s"
        (
            {
                echo "===== QoS side of ${pair_tag}, $(date -u) ====="
                echo "Command: iperf3 -c ${SERVER_IP} -B ${QOS_BIND_IP} -p ${QOS_PORT} -u -b ${qos_rate}M -t ${DURATION} -O ${OMIT} -i 1"
            } > "${qos_log}"
            run_logged "${qos_log}" iperf3 -c "${SERVER_IP}" -B "${QOS_BIND_IP}" -p "${QOS_PORT}" -u -b "${qos_rate}M" -t "${DURATION}" -O "${OMIT}" -i 1
        ) &
        local qos_pid=$!

        (
            {
                echo "===== non-QoS side of ${pair_tag}, $(date -u) ====="
                echo "Command: iperf3 -c ${SERVER_IP} -B ${NON_QOS_BIND_IP} -p ${NON_QOS_PORT} -u -b ${non_qos_rate}M -t ${DURATION} -O ${OMIT} -i 1"
            } > "${non_qos_log}"
            run_logged "${non_qos_log}" iperf3 -c "${SERVER_IP}" -B "${NON_QOS_BIND_IP}" -p "${NON_QOS_PORT}" -u -b "${non_qos_rate}M" -t "${DURATION}" -O "${OMIT}" -i 1
        ) &
        local non_qos_pid=$!

        set +e
        wait "${qos_pid}"
        qos_status=$?
        wait "${non_qos_pid}"
        non_qos_status=$?
        set -e

        {
            echo "QoS exit status: ${qos_status}"
            echo "non-QoS exit status: ${non_qos_status}"
            echo
        } >> "${summary_file}"

        if [ "${qos_status}" -eq 0 ] && [ "${non_qos_status}" -eq 0 ]; then
            progress "Finished two-flow QoS ${qos_rate} Mbps + non-QoS ${non_qos_rate} Mbps"
        else
            progress "FAILED two-flow QoS ${qos_rate} Mbps + non-QoS ${non_qos_rate} Mbps"
        fi

        sleep "${PAUSE}"
    done

    progress "Completed two-flow sharing test"
    echo "${summary_file}"
}

run_shared_qer() {
    local summary_file="${log_dir}/dn-shared-qer-summary-${timestamp}.log"
    local first_log="${log_dir}/dn-shared-qer-port-${QOS_PORT}-${timestamp}.log"
    local second_log="${log_dir}/dn-shared-qer-port-${QOS_SECOND_PORT}-${timestamp}.log"
    local first_status=0
    local second_status=0

    {
        echo "# Two 5-tuples associated with the same selected GBR QER"
        echo "# Their aggregate result must be limited by qos_mbr_mbps, not once per flow."
        echo "# date_utc: $(date -u)"
        echo "# git_commit: ${commit}"
        echo "# server_ip: ${SERVER_IP}"
        echo "# bind_ip: ${QOS_BIND_IP}"
        echo "# ports: ${QOS_PORT} ${QOS_SECOND_PORT}"
        echo "# offered_rate_per_flow_mbps: ${SHARED_QER_RATE_MBPS}"
        echo "# qos_gbr_mbps: ${QOS_GBR_MBPS}"
        echo "# qos_mbr_mbps: ${QOS_MBR_MBPS}"
        echo
    } > "${summary_file}"

    progress "Running two QoS 5-tuples sharing one QER for ${DURATION}s"
    run_logged "${first_log}" iperf3 -c "${SERVER_IP}" -B "${QOS_BIND_IP}" \
        -p "${QOS_PORT}" -u -b "${SHARED_QER_RATE_MBPS}M" -t "${DURATION}" \
        -O "${OMIT}" -i 1 &
    local first_pid=$!
    run_logged "${second_log}" iperf3 -c "${SERVER_IP}" -B "${QOS_BIND_IP}" \
        -p "${QOS_SECOND_PORT}" -u -b "${SHARED_QER_RATE_MBPS}M" -t "${DURATION}" \
        -O "${OMIT}" -i 1 &
    local second_pid=$!

    set +e
    wait "${first_pid}"
    first_status=$?
    wait "${second_pid}"
    second_status=$?
    set -e

    {
        echo "first flow log: ${first_log}"
        echo "second flow log: ${second_log}"
        echo "first flow exit status: ${first_status}"
        echo "second flow exit status: ${second_status}"
    } >> "${summary_file}"

    if [ "${first_status}" -eq 0 ] && [ "${second_status}" -eq 0 ]; then
        progress "Finished shared-QER test"
    else
        progress "FAILED shared-QER test"
    fi
    echo "${summary_file}"
}

if [ "${mode}" != "-h" ] && [ "${mode}" != "--help" ] && [ "${mode}" != "help" ]; then
    progress "Logs will be written under ${log_dir}"
    progress "AMBR=${UE_AMBR_MBPS} Mbps, GBR=${QOS_GBR_MBPS} Mbps, MBR=${QOS_MBR_MBPS} Mbps"
    progress "QoS rates: ${QOS_RATES}"
    progress "non-QoS rates: ${NON_QOS_RATES}"
    progress "two-flow pairs: ${TWO_FLOW_PAIRS}"
fi

case "${mode}" in
    qos)
        run_sweep "qos" "${QOS_BIND_IP}" "${QOS_PORT}" "${QOS_RATES}"
        ;;
    non-qos | default)
        run_sweep "non-qos" "${NON_QOS_BIND_IP}" "${NON_QOS_PORT}" "${NON_QOS_RATES}"
        ;;
    both)
        run_sweep "qos" "${QOS_BIND_IP}" "${QOS_PORT}" "${QOS_RATES}"
        run_sweep "non-qos" "${NON_QOS_BIND_IP}" "${NON_QOS_PORT}" "${NON_QOS_RATES}"
        ;;
    two-flow | twoflow)
        run_two_flow
        ;;
    shared-qer | shared_qer)
        run_shared_qer
        ;;
    all)
        run_sweep "qos" "${QOS_BIND_IP}" "${QOS_PORT}" "${QOS_RATES}"
        run_sweep "non-qos" "${NON_QOS_BIND_IP}" "${NON_QOS_PORT}" "${NON_QOS_RATES}"
        run_two_flow
        run_shared_qer
        ;;
    -h | --help | help)
        usage
        exit 0
        ;;
    *)
        usage
        exit 2
        ;;
esac

progress "Logs written under ${log_dir}"
