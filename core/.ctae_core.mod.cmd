savedcmd_ctae_core.mod := printf '%s\n'   ctae_core.o | awk '!x[$$0]++ { print("./"$$0) }' > ctae_core.mod
