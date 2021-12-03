from typing import *

import datetime
import jwt
import pathlib
import requests

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend


class Neoapp:
    """
    Check certificate methods
    """
    allowed_issuers: List[str] = []
    check_signature: bool = True
    cert_expiration_secs: Optional[int] = None
    verify_exp: bool = True
    verify_aud: bool = True
    audience: Optional[str] = None
    local_temp_directory = '/tmp/'
    get_from_token = ['sub', 'locale']

    def __init__(self, config):
        if 'ALLOWED_ISSUERS' in config:
            self.allowed_issuers = config.get('ALLOWED_ISSUERS')
        self.check_signature = config.get('CHECK_SIGNATURE', True)
        self.cert_expiration_secs = config.get('CERT_EXPIRATION')
        if not isinstance(self.cert_expiration_secs, int) or self.cert_expiration_secs <= 0:
            self.cert_expiration_secs = None
        self.verify_aud = config.get('VERIFY_AUD', True)
        self.verify_exp = config.get('VERIFY_EXP', True)
        self.audience = config.get('AUD')
        if config.get('LOCAL_TEMP_DIRECTORY'):
            if pathlib.Path(config.get('LOCAL_TEMP_DIRECTORY')).is_dir():
                self.local_temp_directory = config.get('LOCAL_TEMP_DIRECTORY')

    def local_cert_filename(self, issuer: str) -> str:
        """
        Issuer name is URI.
        Removes some chars, to make safe to be filename
        """
        return self.local_temp_directory + issuer.replace('://', '-').replace('/', '-')

    def get_cert_locally(self, issuer: str) -> Optional[bytes]:
        """
        Gets certificate from local /tmp folder, checking if certificate is not expired locally
        issuer: URI
        Returns: certificate data as bytes
        """
        cert_filename = Neoapp.local_cert_filename(self, issuer)
        fname = pathlib.Path(cert_filename)
        if not fname.exists():
            return None

        # If we need to check certificate expiration,
        if self.cert_expiration_secs:
            stat = fname.stat()
            now_timestamp = datetime.datetime.now().timestamp()  # in seconds, local time
            cert_created_timestamp = stat.st_ctime  # file info is local time
            if now_timestamp - cert_created_timestamp > self.cert_expiration_secs:
                return None
        try:
            with open(cert_filename, 'rb') as f:
                data = f.read()
            return data
        except FileNotFoundError:  # already checked with exists(). any other?
            return None

    def get_cert_from_issuer(self, issuer) -> Optional[bytes]:
        """
        Gets certificate from issuer and saves to local tmp folder
        """
        try:
            # Get well-known configuration from issuer, take certificate endpoint
            issuer_config = requests.get(issuer + '/.well-known/openid-configuration').json()
            if 'jwks_uri' in issuer_config:
                certs_json = requests.get(issuer_config.get('jwks_uri')).json()
                if isinstance(certs_json.get('keys'), list):
                    for cert in certs_json.get('keys'):
                        if cert.get('alg') == 'RS256' \
                                and cert.get('use') == 'sig' \
                                and isinstance(cert.get('x5c'), list):
                            x5c = cert['x5c'][0]
                            cert_text = b"-----BEGIN CERTIFICATE-----\n" + \
                                       bytes(x5c, encoding='ascii') + \
                                       b"\n-----END CERTIFICATE-----"
                            with open(Neoapp.local_cert_filename(self, issuer), 'wb') as f:
                                f.write(cert_text)
                            return cert_text
        except:  # everything!
            pass
        return None

    def from_authorization_header(
            self,
            headers: Dict[str, str],
            attributes: Optional[List[str]] = None,
            access_token=None
    ) -> Optional[Dict[str, str]]:
        """
        Checks if access token in Authorization header is signed with correct certificate.
        Returns: dict of attributes by list (default is ['sub', 'locale']), extracted from access token.
        """
        if 'Authorization' in headers:
            auth: str = headers.get('Authorization')
            if auth.startswith('Bearer '):
                access_token = auth[7:]
        if not access_token:
            return None

        attributes = attributes if attributes is not None else self.get_from_token

        def get_from(source: Dict[str, str], by_list: List[str]) -> Dict[str, str]:
            return {k: source.get(k) for k in by_list}

        # 1. Decode certificate without signature verification
        unverified_data = jwt.decode(access_token, options={'verify_signature': False})
        if not self.check_signature:  # if fast way is chosen
            return get_from(unverified_data, attributes)

        # 2. Take token issuer and check, if the issuer is allowed in the configuration
        issuer = unverified_data.get('iss')
        if issuer not in self.allowed_issuers:
            return None

        # 3. Take certificate for signature verification from local temp folder
        # This also checks certificate file creation date against CERT_EXPIRATION option
        cert = self.get_cert_locally(issuer)

        # 4. Is there is no local certificate, or it is expired, get certificate from the issuer
        if cert is None:
            cert = Neoapp.get_cert_from_issuer(self, issuer)

        # If certificate was not obtained, we can not validate token, so don't know what to do
        if cert is None:
            return None

        # 5. Construct public key for signature verification
        cert_obj = load_pem_x509_certificate(cert, default_backend())
        public_key = cert_obj.public_key()
        try:
            data = jwt.decode(
                access_token, public_key, algorithms=["RS256"],
                audience=self.audience,
                options={"verify_exp": self.verify_exp, "verify_aud": self.verify_aud}
            )
            return get_from(data, attributes)
        except (
                jwt.exceptions.InvalidSignatureError,
                jwt.exceptions.InvalidAudienceError,
                jwt.exceptions.ExpiredSignatureError
        ):
            pass
        return None
