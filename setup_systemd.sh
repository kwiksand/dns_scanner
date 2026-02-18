#!/bin/bash

# Get current directory and user
CUR_PWD=$(pwd)
CUR_USER=$(whoami)

echo "Setting up systemd units for $CUR_USER in $CUR_PWD..."
tmpdir="$(mktemp -d)"

# Prepare the service file from template
sed "s|{{PWD}}|$CUR_PWD|g; s|{{USER}}|$CUR_USER|g" systemd/dns-scanner.service.template >$tmpdir/dns-scanner.service

# Copy to systemd directory
echo "Copying files to /etc/systemd/system/..."
sudo cp $tmpdir/dns-scanner.service /etc/systemd/system/
sudo cp systemd/dns-scanner.timer /etc/systemd/system/

# Reload and enable
echo "Reloading systemd and enabling timer..."
sudo systemctl daemon-reload
sudo systemctl enable --now dns-scanner.timer

echo "Setup complete. Timer status:"
systemctl list-timers dns-scanner.timer
