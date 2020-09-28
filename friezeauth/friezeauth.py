__all__ = [
    'TrustType',
    'Certificate',
    'CertAuthInternal',
    'CertFormat',
    'CertType'
]

import base64
import datetime as dt
import enum
import hashlib
import json
import os
import pprint
import secrets
import string
import time
import toml

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class CertFormat(enum.Enum):
    SSH = 1
    PEM = 2


class CertType(enum.Enum):
    CERTAUTH  = 'certauth'
    SERVER    = 'server'
    CLIENT    = 'client'
    USER      = 'user'


class TrustType(enum.Enum):
    INTERNAL    = 'internal'
    LETSENCRYPT = 'letsencrypt'


class Certificate(object):

    def __init__(self, authority, subjects):

        if type(subjects)==str:
            subjects = [subjects]

        self.authority = authority
        self.primary_subject = None
        self.subjects  = []
        for subject in subjects:
            ns_subject = subject.strip()
            if not self.primary_subject:
                self.primary_subject = ns_subject
            self.subjects.append(ns_subject)
            self.subjects.sort()
        self.csr = None

    @property
    def certificate(self):
        """Return a pyca/cryptography object representing an issued certificate"""
        try:
            with open(self.files['chain'], 'rb') as f:
                return x509.load_pem_x509_certificate(f.read(), default_backend())
        except:
            return None

    def create_csr(self, cert_type, random_alt_subject=False, force=False):
        """Use pyca/cryptography to create CSR object"""
        if not force and self.is_valid:
            print("This certificate is already issued and valid, not issuing CSR")
            return

        # Generate a private key and store it
        subject_key =\
            rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )

        if not os.path.exists(self.path()):
            os.makedirs(self.path(), mode=0o700)
        os.chmod(self.path(), 0o700)
        with open(os.open(self.files['private'], os.O_CREAT|os.O_WRONLY, 0o600), 'wb') as f:
            f.write(
                subject_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )


        # Use pyca/cryptography to generate csr
        subjects = list(self.subjects)
        if random_alt_subject:
            random_domain = base64.b16encode(os.urandom(5)).decode('utf-8')
            random_domain = f'{random_domain}.{self.authority.domain.domain}'.lower()
            subjects.append(random_domain)

        csrb =\
            x509.CertificateSigningRequestBuilder(
            ).subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, self.primary_subject),
                ])
            ).add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(subject) for subject in subjects]
                ),
                critical=False,
            )

        # Specify how certificate is to be used
        if cert_type==CertType.SERVER:
            csrb =\
                csrb.add_extension(
                    x509.KeyUsage(
                        True,       # digital signature
                        True,       # content commitment/non repudiation
                        True,       # key encipherment
                        False,      # data encipherment
                        False,      # key aggreement
                        False,      # key cert sign
                        False,      # crl sign
                        False,      # encipher only
                        False,      # decipher only
                    ), critical=True
                ).add_extension(
                    x509.ExtendedKeyUsage([
                        ExtendedKeyUsageOID.SERVER_AUTH
                    ]),
                    critical=False
                )
        elif cert_type==CertType.CLIENT:
            csrb =\
                csrb.add_extension(
                    x509.KeyUsage(
                        True,       # digital signature
                        True,       # content commitment/non repudiation
                        False,      # key encipherment
                        False,      # data encipherment
                        False,      # key aggreement
                        False,      # key cert sign
                        False,      # crl sign
                        False,      # encipher only
                        False,      # decipher only
                    ),
                    critical=True
                ).add_extension(
                    x509.ExtendedKeyUsage([
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    ]),
                    critical=False
                )
        else:
            raise RuntimeError("Type of certificate must be specified")

        # Sign the sorry business
        csr = csrb.sign(subject_key, hashes.SHA256(), default_backend())

        return csr

    @property
    def files(self):
        return {
            'chain'   : os.path.join(self.path(), 'chain.crt'),
            'private' : os.path.join(self.path(), 'private.pem'),
        }

    @property
    def inferred_name(self):
        return hashlib.sha256(','.join(self.subjects).encode('utf-8')).hexdigest()

    @property
    def is_valid(self):
        # Validate path,
        file_structure_ok = (
            os.path.exists(self.files['chain'])
            and os.path.exists(self.files['private'])
        )

        if file_structure_ok  is False:
            return False

        cert = self.certificate
        current_time = dt.datetime.utcnow()

        return current_time>=cert.not_valid_before and current_time<cert.not_valid_after

    def path(self, rootdir=None):
        # The same certificate *may* map to multiple aliases. We need a way to reproducibly
        # go from aliases -> on-disk directory.
        if not rootdir:
            rootdir = self.authority.certdir
        return os.path.join(rootdir, self.inferred_name)

    @property
    def private_key(self):
        """Return bytes of the private key used to sign the certificate"""
        try:
            with open(self.files['private'], 'rb') as f:
                return\
                    serialization.load_pem_private_key(
                        f.read(),
                        password=self.rootca_password,
                        backend=default_backend()
                    )
        except:
            return None


class CertAuthBase(object):

    def __init__(self, domain):

        self.domain = domain
        with open(os.path.expanduser(os.getenv('FRIEZE_AUTH_CONF')), 'r') as f:
            raw_cfg = toml.loads(f.read())
            self.run_home = raw_cfg['home']
            self.config = raw_cfg[self.domain]

        if not os.path.exists(self.rootdir):
            os.makedirs(self.rootdir, mode=0o700)

        os.chmod(self.rootdir, 0o700)

    def issue_certificate(self, *args, cert_format=CertFormat.SSH, **kwargs):
        """By default, return SSH formatted certificates."""
        return {
            CertFormat.SSH : self._issue_ssh_certificate,
            CertFormat.PEM : self._issue_pem_certificate,
        }[cert_format](*args, **kwargs)

    @property
    def certdir(self):

        return os.path.join(self.rootdir, 'certs')

    @property
    def rootdir(self):

        return os.path.join(self.run_home, 'domains', self.domain, 'trust', self.trust_type.value)


class CertAuthInternal(CertAuthBase):

    trust_type = TrustType.INTERNAL

    def __init__(self, domain):

        super().__init__(domain)

        self.pw_file       = os.path.join(self.rootdir, 'ca.pw')
        self.priv_key_file = os.path.join(self.rootdir, 'ca.pem')
        self.pub_crt_file  = os.path.join(self.rootdir, 'ca_pub.crt')
        self.pub_ssh_file  = os.path.join(self.rootdir, 'ca_pub.ssh')

    def certificate(self, certformat=CertFormat.PEM):
        if certformat == CertFormat.PEM:
            with open(self.pub_crt_file, 'rb') as f:
                return x509.load_pem_x509_certificate(f.read(), default_backend())
        elif certformat == CertFormat.SSH:
            with open(self.pub_ssh_file, 'rb') as f:
                return serialization.load_ssh_public_key(f.read(), default_backend())

    def initialize(self):

        # Not bothering with refreshing
        if self.is_valid:
            print(f"Not refreshing backend trust [{self.trust_type.value}]")
            return

        # Generate a private key off the bat
        newca_priv_key =\
            rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend(),
            )

        # What are we signing?
        newca_subject =\
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.config['country']),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.config['province']),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.config['locality']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config['org']),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.config['org_unit']),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.config['contact']),
                x509.NameAttribute(NameOID.COMMON_NAME, "%s Certificate Authority" % self.config['org']),
            ])

        # Valid from
        newca_valid_from = dt.datetime.utcnow()
        newca_valid_until = None

        # Use this to sign the key
        signing_key = None

        if self.is_intermediate_ca:

            signing_key = self.rootca_privkey

            # Validity is the lesser of ten years and validity of root
            newca_valid_until = newca_valid_from+dt.timedelta(days=10*365.25)
            if newca_valid_until > self.rootca_cert.not_valid_after:
                newca_valid_until = self.rootca_cert.not_valid_after

            # In this case we're going to be singing a CSR
            csr =\
                x509.CertificateSigningRequestBuilder()\
                    .subject_name(newca_subject)\
                    .sign(newca_priv_key, hashes.SHA256(), default_backend())

            signable =\
                x509.CertificateBuilder()\
                    .subject_name(csr.subject)\
                    .issuer_name(self.rootca_cert.subject)\
                    .public_key(csr.public_key())\
                    .serial_number(x509.random_serial_number())\
                    .not_valid_before(newca_valid_from)\
                    .not_valid_after(newca_valid_until)
        else:

            # Self signed
            signing_key = newca_priv_key

            # validity is 10 years
            newca_valid_until = newca_valid_from+datetime.timedelta(days=10*365.25)

            signable =\
                x509.CertificateBuilder()\
                    .subject_name(newca_subject)\
                    .issuer_name(newca_subject)\
                    .public_key(newca_priv_key.public_key())\
                    .serial_number(x509.random_serial_number())\
                    .not_valid_before(newca_valid_from)\
                    .not_valid_after(newca_valid_until)

        cert = signable.sign(signing_key, hashes.SHA256(), default_backend())

        password=str().join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)).encode()

        with open(os.open(self.priv_key_file, os.O_CREAT|os.O_WRONLY, 0o600), 'wb') as f:
            f.write(newca_priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=\
                    serialization.BestAvailableEncryption(password)
            ))
        with open(os.open(self.pub_crt_file, os.O_CREAT|os.O_WRONLY, 0o600), 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(os.open(self.pub_ssh_file, os.O_CREAT|os.O_WRONLY, 0o600), 'wb') as f:
            f.write(newca_priv_key.public_key().public_bytes(
                        encoding=serialization.Encoding.OpenSSH,
                        format=serialization.PublicFormat.OpenSSH
                    ))
        with open(os.open(self.pw_file, os.O_CREAT|os.O_WRONLY, 0o600), 'w') as f:
            f.write(password.decode())

        print("New certificate authority created for [%s]. Files:" % self.config['org'])
        print("   Private Key: [%s]" % self.priv_key_file)
        print("   Certificate: [%s]" % self.pub_crt_file)
        print("   Password:    [%s]" % self.pw_file)
        print("Certificate authority will remain valid until [%s]" % newca_valid_until)

    @property
    def is_intermediate_ca(self):
        try:
            setattr(self, '_rootca_private_key_file', os.path.expanduser(self.config['rootca']['private_key']))
            setattr(self, '_rootca_certificate_file', os.path.expanduser(self.config['rootca']['certificate']))
            setattr(self, '_rootca_password', self.config['rootca']['password'].encode())
        except KeyError:
            setattr(self, '_rootca_private_key_file', str())
            setattr(self, '_rootca_certificate_file', str())
            setattr(self, '_rootca_password', str())

        return os.path.exists(self._rootca_private_key_file) and os.path.exists(self._rootca_certificate_file)

    @property
    def is_valid(self):
        """For now, just check the existence of these files to make sure that
        the CA looks to be in good shape"""
        file_structure_ok = (
            os.path.exists(self.pw_file)
            and os.path.exists(self.priv_key_file)
            and os.path.exists(self.pub_crt_file)
            and os.path.exists(self.pub_ssh_file)
        )

        if file_structure_ok  is False:
            return False

        cert = self.certificate()
        current_time = dt.datetime.utcnow()

        return current_time>=cert.not_valid_before and current_time<cert.not_valid_after

    def _issue_pem_certificate(self,
                               subject,
                               cert_type,
                               command=None,
                               remote_user='root',
                               user_ip=None,
                               validity_length=120,
                               valid_src_ips=None,
                               serialize_to_dir=None):

        cert = Certificate(self, subject)
        if cert.is_valid is True:
            print(f"Not refreshing cert trust [{cert.chain.subject.rfc4514_string()}]")
            return

        csr = cert.create_csr(cert_type)

        valid_from  = dt.datetime.utcnow()
        valid_until = valid_from+dt.timedelta(seconds=validity_length)

        signable =\
            x509.CertificateBuilder()\
                .subject_name(csr.subject)\
                .issuer_name(self.certificate().subject)\
                .public_key(csr.public_key())\
                .serial_number(x509.random_serial_number())\
                .not_valid_before(valid_from)\
                .not_valid_after(valid_until)

        for ext in csr.extensions:
            signable = signable.add_extension(ext.value, critical=ext.critical)

        # Sign certificate and push it to storage
        signed_cert = signable.sign(self.private_key, hashes.SHA256(), default_backend())
        with open(os.open(cert.files['chain'], os.O_CREAT|os.O_WRONLY, 0o600), 'wb') as f:
            f.write(signed_cert.public_bytes(serialization.Encoding.PEM))

        return signed_cert

    def _issue_ssh_certificate(self, subject, cert_type, command=None, remote_user='root', user_ip=None, validity_length=300, valid_src_ips=None, serialize_to_dir=None):
        raise NotImplementedError("No implementation yet, take a look at frieze for bless-ng-based implementation")

    @property
    def private_key_password(self):
        with open(self.pw_file, 'r') as f:
            return f.read().encode()

    @property
    def private_key(self):
        with open(self.priv_key_file, 'rb') as f:
            return \
                serialization.load_pem_private_key(
                    f.read(),
                    password=self.private_key_password,
                    backend=default_backend()
                )

    @property
    def rootca_cert(self):
        if self.is_intermediate_ca:
            with open(self._rootca_certificate_file, 'rb') as f:
                rootca_cert =\
                    x509.load_pem_x509_certificate(f.read(), default_backend())
            return rootca_cert
        else:
            return None

    @property
    def rootca_password(self):
        if self.is_intermediate_ca:
            return self._rootca_password
        else:
            return None

    @property
    def rootca_privkey(self):
        if self.is_intermediate_ca:
            with open(self._rootca_private_key_file, 'rb') as f:
                rootca_key =\
                    serialization.load_pem_private_key(
                        f.read(),
                        password=self.rootca_password,
                        backend=default_backend()
                    )
            return rootca_key
        else:
            return None

