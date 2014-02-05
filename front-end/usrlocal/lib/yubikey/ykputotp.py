#!/usr/bin/python
import subprocess

subprocess.call(["/usr/lib/qubes/qrexec_client_vm", "dom0", "qubes.2fa", "/bin/cat", "/home/user/.yubikey"])
subprocess.call(["rm", "/home/user/.yubikey"])

