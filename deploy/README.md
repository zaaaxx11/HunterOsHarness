# Production deploy artifacts

These files make the chat gateway survive reboots and crashes. They are
**templates** — nothing here is activated automatically. Review, copy to the
host, then enable explicitly.

## 1. Secrets

```bash
sudo install -m 600 /dev/null /etc/hunter-gateway.env
sudo nano /etc/hunter-gateway.env          # fill from gateway.env.example
```

Never commit a populated env file; `deploy/.gitignore` blocks it.

## 2. Gateway service (auto-restart on crash + reboot)

```bash
sudo cp deploy/hunter-gateway.service /etc/systemd/system/hunter-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now hunter-gateway
systemctl status hunter-gateway           # verify
journalctl -u hunter-gateway -f           # live logs
```

The unit uses `Restart=always` and `Wants=network-online.target`, so a crash
or a reboot brings the bot back without manual `nohup`/`setsid` juggling.
Adjust `User`, `WorkingDirectory`, `ExecStart` and `ReadWritePaths` if the
checkout/venv live elsewhere.

## 3. Log rotation

```bash
sudo cp deploy/hunter-gateway.logrotate /etc/logrotate.d/hunter-gateway
sudo logrotate -d /etc/logrotate.d/hunter-gateway   # dry-run
```

## 4. One-time migration from the `nohup` process

Stop the old process first so the lock file is released, then start the unit:

```bash
# find and stop the old gateway (do NOT pkill -f blindly)
pgrep -af 'hunter.cli.main gateway start'
kill <pid>
sudo systemctl enable --now hunter-gateway
```
