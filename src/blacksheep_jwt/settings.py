from datetime import timedelta
from typing import Optional
from typing import Union

import attr
from attr.validators import instance_of
from blacksheep_jwt.utils import str2bytes
from blacksheep_jwt.utils import str2timedelta


@attr.s(auto_attribs=True)
class JwtSettings:
    signing_key: str
    verifying_key: Optional[str] = None
    algorithm: str = 'HS256'
    issuer: Optional[str] = None
    audience: Optional[str] = None
    jwk_url: Optional[str] = None
    leeway: Union[float, timedelta] = 0.0

    auth_header_type: bytes = attr.ib(
        default=b'Bearer',
        converter=str2bytes,
        validator=instance_of(bytes),
    )
    auth_header_name: bytes = attr.ib(
        default=b'Authorization',
        converter=str2bytes,
        validator=instance_of(bytes),
    )
    user_id_field: str = 'id'
    user_id_claim: str = 'user_id'

    token_type_claim: str = 'token_type'
    jti_claim: str = 'jti'

    access_token_lifetime: timedelta = attr.ib(
        default=timedelta(minutes=5),
        converter=str2timedelta,
        validator=instance_of(timedelta),
    )
    refresh_token_lifetime: timedelta = attr.ib(
        default=timedelta(days=1),
        converter=str2timedelta,
        validator=instance_of(timedelta),
    )

    auth_token_classes: tuple[str] = ('blacksheep_jwt.tokens.AccessToken',)
