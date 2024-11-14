import os
import os.path
import subprocess
import sys
import time

from tlsimpl.client import TLSSocket

proc = None
try:
    openssl_version = subprocess.run(
        ["openssl", "version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
    )
    cert_dir = os.path.join(os.path.dirname(__file__), "../certs")
    if not os.path.isdir(cert_dir):
        os.mkdir(cert_dir)
    has_key = os.path.isfile(os.path.join(cert_dir, "server.key")) and os.path.isfile(
        os.path.join(cert_dir, "server.csr")
    )
    has_pem = os.path.isfile(os.path.join(cert_dir, "server.pem"))
    if not has_key:
        print("Generating a server key and signing request...")
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-subj",
                "/CN=US/",
                "-newkey",
                "rsa:4096",
                "-nodes",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
                "-quiet",
            ],
            cwd=cert_dir,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if not has_pem:
        print("Generating a server certificate...")
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-sha256",
                "-days",
                "365",
                "-in",
                "server.csr",
                "-signkey",
                "server.key",
                "-out",
                "server.pem",
            ],
            cwd=cert_dir,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    print("Starting an openssl server on port 8080...")
    proc = subprocess.Popen(
        ["openssl", "s_server", "-port", "8080", "-trace", "-key", "server.key"],
        cwd=cert_dir,
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    time.sleep(1)

except FileNotFoundError:
    print("Couldn't find openssl command, using example.com instead")
except subprocess.CalledProcessError:
    print("Error while running openssl, using example.com instead")

try:
    if proc is None:
        s = TLSSocket.create_connection(("example.com", 443))
    else:
        s = TLSSocket.create_connection(("127.0.0.1", 8080))
    s.close()
finally:
    if proc is not None:
        time.sleep(1)
        proc.terminate()
