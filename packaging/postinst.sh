#!/bin/sh
set -e
echo "Reloading systemd daemon..."
systemctl daemon-reload
echo "Enabling mace service to start on boot..."
systemctl enable mace.service
echo "Starting mace service..."
systemctl start mace.service
