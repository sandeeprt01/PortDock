import os
import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(BASE_DIR, "certificates")

CA_KEY_FILE = os.path.join(CERT_DIR, "portdock-ca.key")
CA_CERT_FILE = os.path.join(CERT_DIR, "portdock-ca.crt")

SERVER_KEY_FILE = os.path.join(CERT_DIR, "localhost.key")
SERVER_CERT_FILE = os.path.join(CERT_DIR, "localhost.crt")


def create_certificate_folder():
    os.makedirs(CERT_DIR, exist_ok=True)


def generate_ca():
    print("Creating PortDock Local CA...")

    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "PortDock Local CA"
        )
    ])

    now = datetime.now(timezone.utc)

    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=None
            ),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None
            ),
            critical=True
        )
        .sign(
            private_key=ca_key,
            algorithm=hashes.SHA256()
        )
    )

    with open(CA_KEY_FILE, "wb") as file:
        file.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(CA_CERT_FILE, "wb") as file:
        file.write(
            ca_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )

    print("CA created.")

    return ca_key, ca_certificate


def generate_server_certificate(ca_key, ca_certificate):
    print("Creating *.localhost certificate...")

    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            "*.localhost"
        )
    ])

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("*.localhost"),
                x509.IPAddress(
                    ipaddress.ip_address("127.0.0.1")
                )
            ]),
            critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False
        )
        .sign(
            private_key=ca_key,
            algorithm=hashes.SHA256()
        )
    )

    with open(SERVER_KEY_FILE, "wb") as file:
        file.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(SERVER_CERT_FILE, "wb") as file:
        file.write(
            certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )

    print("Server certificate created.")


def setup_tls():
    create_certificate_folder()

    print()
    print("==============================================")
    print("           PORTDOCK HTTPS SETUP")
    print("==============================================")
    print()

    if (
        os.path.exists(CA_KEY_FILE)
        and os.path.exists(CA_CERT_FILE)
        and os.path.exists(SERVER_KEY_FILE)
        and os.path.exists(SERVER_CERT_FILE)
    ):
        print("Certificates already exist.")
        print()
        return

    ca_key, ca_certificate = generate_ca()

    generate_server_certificate(
        ca_key,
        ca_certificate
    )

    print()
    print("HTTPS certificates created successfully.")
    print()
    print("Files created inside:")
    print(CERT_DIR)
    print()
    print("Next step: trust the PortDock Local CA in Windows.")
    print()


if __name__ == "__main__":
    setup_tls()