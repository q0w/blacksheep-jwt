from datetime import timedelta
from typing import Optional
from typing import Union

import attr
import jwt
from attr.validators import instance_of
from attr.validators import optional
from blacksheep_jwt.errors import TokenBackendError
from blacksheep_jwt.settings import JwtSettings
from jwt import algorithms
from jwt import InvalidAlgorithmError
from jwt import InvalidTokenError

ALLOWED_ALGORITHMS = (
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
)


@attr.s
class TokenBackend:
    signing_key = attr.ib(
        type=str,
        validator=instance_of(str),
    )
    verifying_key = attr.ib(
        default=None,
        type=Optional[str],
        validator=optional(instance_of(str)),
    )
    algorithm = attr.ib(
        default='HS256',
        type=str,
        validator=instance_of(str),
    )
    audience = attr.ib(
        default=None,
        type=Optional[str],
        validator=optional(instance_of(str)),
    )
    issuer = attr.ib(
        default=None,
        type=Optional[str],
        validator=optional(instance_of(str)),
    )
    jwk_url = attr.ib(
        default=None,
        type=Optional[str],
        validator=optional(instance_of(str)),
    )
    jwks_client = attr.ib()
    leeway = attr.ib(
        default=0.0,
        type=Union[float, timedelta],
        validator=instance_of((float, timedelta)),
    )

    @jwks_client.default
    def check_jwk_url(self):
        if self.jwk_url:
            return jwt.PyJWKClient(self.jwk_url)
        else:
            return None

    def __attrs_post_init__(self):
        if self.algorithm.startswith('HS'):
            self.verifying_key = self.signing_key

    @algorithm.validator
    def _validate_algorithm(self, attribute, value):
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

    def get_verifying_key(self, token):
        if self.algorithm.startswith('HS'):
            return self.signing_key

        if self.jwks_client:
            return self.jwks_client.get_signing_key_from_jwt(token).key

        return self.verifying_key

    def encode(self, payload):
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

    def decode(self, token, verify=True):
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
    def from_configuration(cls, settings: JwtSettings):
        return cls(
            algorithm=settings.algorithm,
            signing_key=settings.signing_key,
            verifying_key=settings.verifying_key,
            audience=settings.audience,
            issuer=settings.issuer,
            jwk_url=settings.jwk_url,
            leeway=settings.leeway,
        )
