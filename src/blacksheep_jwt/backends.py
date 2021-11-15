from datetime import timedelta
from typing import Any
from typing import Dict
from typing import Optional
from typing import Union

import attr
import jwt
from blacksheep_jwt.errors import TokenBackendError
from blacksheep_jwt.settings import JwtSettings
from jwt import algorithms
from jwt import InvalidAlgorithmError
from jwt import InvalidTokenError
from jwt import PyJWKClient

ALLOWED_ALGORITHMS = (
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
)


@attr.define
class TokenBackend:
    signing_key: str
    verifying_key: str = ''
    algorithm: str = attr.ib(default='HS256')
    audience: Optional[str] = None
    issuer: Optional[str] = None
    jwk_url: Optional[str] = None
    jwks_client: Optional[PyJWKClient] = attr.ib()
    leeway: Union[float, timedelta] = 0.0

    @jwks_client.default
    def check_jwk_url(self) -> Optional[PyJWKClient]:
        if self.jwk_url:
            return PyJWKClient(self.jwk_url)
        else:
            return None

    def __attrs_post_init__(self):
        if self.algorithm.startswith('HS'):
            self.verifying_key = self.signing_key

    @algorithm.validator
    def _validate_algorithm(self, attribute, value) -> None:
        if value not in ALLOWED_ALGORITHMS:
            raise TokenBackendError(
                f"Unrecognized algorithm type '{value}'.",
            )

        if (
            value in algorithms.requires_cryptography
            and not algorithms.has_crypto
        ):
            raise TokenBackendError(
                f'You must have cryptography installed to use {value}.',
            )

    def get_verifying_key(self, token: str) -> str:
        if self.algorithm.startswith('HS'):
            return self.signing_key

        if self.jwks_client:
            return self.jwks_client.get_signing_key_from_jwt(token).key

        return self.verifying_key

    def encode(self, payload: Dict[str, Any]) -> str:
        jwt_payload = payload.copy()
        if self.audience is not None:
            jwt_payload['aud'] = self.audience
        if self.issuer is not None:
            jwt_payload['iss'] = self.issuer

        token = jwt.encode(
            jwt_payload,
            self.signing_key,
            algorithm=self.algorithm,
        )
        return token

    def decode(self, token: str, verify=True) -> Dict[str, Any]:
        try:
            return jwt.decode(
                token,
                self.get_verifying_key(token),
                algorithms=[self.algorithm],
                verify=verify,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={
                    'verify_aud': self.audience is not None,
                    'verify_signature': verify,
                },
            )
        except InvalidAlgorithmError as ex:
            raise TokenBackendError('Invalid algorithm specified') from ex
        except InvalidTokenError:
            raise TokenBackendError('Token is invalid or expired')

    @classmethod
    def from_configuration(cls, settings: JwtSettings) -> 'TokenBackend':
        return cls(
            algorithm=settings.algorithm,
            signing_key=settings.signing_key,
            verifying_key=settings.verifying_key,
            audience=settings.audience,
            issuer=settings.issuer,
            jwk_url=settings.jwk_url,
            leeway=settings.leeway,
        )
