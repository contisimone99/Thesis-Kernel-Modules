#!/bin/bash
set -euo pipefail

KO_DIR="/root"
KO_PATH="${KO_PATH:-$(ls -1 ${KO_DIR}/*.ko 2>/dev/null | head -n 1 || true)}"

# If there is no .ko, do nothing (avoids boot failure)
if [[ -z "${KO_PATH}" || ! -f "${KO_PATH}" ]]; then
  exit 0
fi

# load module (bootstrap info -> hypercall to QEMU)
insmod "${KO_PATH}"

sleep 1

# module name (from modinfo), fallback to basename
MODNAME="$(modinfo -F name "${KO_PATH}" 2>/dev/null || true)"
if [[ -z "${MODNAME}" ]]; then
  MODNAME="$(basename "${KO_PATH}" .ko)"
fi

# remove module (do not fail if already removed)
rmmod "${MODNAME}" 2>/dev/null || true

# remove "our" artifacts on disk
rm -f "${KO_PATH}" 2>/dev/null || true
rm -f /etc/systemd/system/multi-user.target.wants/fx-boot.service 2>/dev/null || true
rm -f /etc/systemd/system/fx-boot.service 2>/dev/null || true

# self-destruction
rm -f /root/fx-boot.sh 2>/dev/null || true

exit 0
