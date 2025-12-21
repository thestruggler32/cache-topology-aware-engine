savedcmd_ctae_monitor.mod := printf '%s\n'   ctae_monitor.o | awk '!x[$$0]++ { print("./"$$0) }' > ctae_monitor.mod
