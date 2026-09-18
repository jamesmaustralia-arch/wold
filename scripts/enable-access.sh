#!/bin/bash
# One-shot access repair for a freshly reinstalled node.
#
# Why this exists as a downloadable script instead of commands you type: the
# MassiveGrid noVNC console drops shifted symbols. Typing >, |, &, _ or : into
# it produces the unshifted character instead, so any normal shell one-liner
# arrives corrupted. Everything needed to FETCH this file — letters, digits,
# '-', '.', '/' — survives that console intact.
#
# It does two things and nothing else:
#   1. installs the operator public key for root
#   2. re-enables password authentication (Debian 12 images ship it off)
set -e

PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE9hxwJfvjm8VnGzd08t2t1XJz2xF7MtXEv7nkAz18MD mac-mini-2026-08'

mkdir -p /root/.ssh
chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
grep -qF "$PUBKEY" /root/.ssh/authorized_keys || echo "$PUBKEY" >> /root/.ssh/authorized_keys
echo "key installed"

# Debian 12 splits sshd config across the main file and a .d directory; a
# PasswordAuthentication no in either one wins, so both get normalised.
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
  [ -f "$f" ] || continue
  sed -i 's/^[[:space:]]*#*[[:space:]]*PasswordAuthentication.*/PasswordAuthentication yes/' "$f"
done
grep -q '^PasswordAuthentication yes' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# PermitRootLogin must also allow password, not just keys.
sed -i 's/^[[:space:]]*#*[[:space:]]*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

systemctl restart ssh || systemctl restart sshd
echo "sshd restarted"
sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'
echo "DONE - node is reachable by key and by password"
