from datetime import timedelta
from typing import Optional
from typing import Tuple
from typing import Union

import attr
from blacksheep_jwt.utils import to_bytes
from blacksheep_jwt.utils import to_timedelta


@attr.define
class JwtSettings:
    signing_key: str
    verifying_key: str = ''
    algorithm: str = 'HS256'
    issuer: Optional[str] = None
    audience: Optional[str] = None
    jwk_url: Optional[str] = None
    leeway: Union[float, timedelta] = 0.0

    auth_header_type: bytes = attr.ib(
        default=b'Bearer',
        converter=to_bytes,
    )
    auth_header_name: bytes = attr.ib(
        default=b'Authorization',
        converter=to_bytes,
    )
    user_id_field: str = 'id'
    user_id_claim: str = 'user_id'

    token_type_claim: str = 'token_type'
    jti_claim: str = 'jti'

    access_token_lifetime: timedelta = attr.ib(
        default=timedelta(minutes=5),
        converter=to_timedelta,
    )
    refresh_token_lifetime: timedelta = attr.ib(
        default=timedelta(days=1),
        converter=to_timedelta,
    )

    auth_token_classes: Tuple[str] = ('blacksheep_jwt.tokens.AccessToken',)
