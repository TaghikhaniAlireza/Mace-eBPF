#!/bin/sh
set -e
echo "Disabling mace service..."
systemctl disable mace.service || true
echo "Reloading systemd daemon..."
systemctl daemon-reload
