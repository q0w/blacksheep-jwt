from datetime import datetime
from datetime import timedelta
from typing import Any
from typing import Dict
from typing import Optional
from uuid import uuid4

import attr
from attr.validators import instance_of
from blacksheep_jwt.backends import TokenBackend
from blacksheep_jwt.errors import TokenBackendError
from blacksheep_jwt.errors import TokenError
from blacksheep_jwt.settings import JwtSettings
from blacksheep_jwt.utils import datetime_from_epoch
from blacksheep_jwt.utils import datetime_to_epoch
from blacksheep_jwt.utils import to_timedelta


@attr.s(repr=False, str=False)
class Token:
    settings: JwtSettings = attr.ib()
    token_backend: TokenBackend = attr.ib(
        init=False,
        default=attr.Factory(
            lambda self: TokenBackend.from_configuration(
                self.settings,
            ),
            takes_self=True,
        ),
    )
    token_type: Optional[str] = None
    lifetime: timedelta = attr.ib(
        init=False,
        default=None,
        converter=to_timedelta,
        validator=instance_of(timedelta),
    )
    token: Optional[str] = None
    payload = attr.ib(init=False, type=Dict[str, Any])
    current_time = attr.ib(init=False)
    is_verify: bool = attr.ib(default=True, validator=instance_of(bool))

    def __attrs_post_init__(self):
        if self.token_type is None or self.lifetime is None:
            raise TokenError('Cannot create token with no type or lifetime')

        self.current_time = datetime.utcnow()
        if self.token is not None:
            try:
                self.payload = self.token_backend.decode(
                    self.token,
                    verify=self.is_verify,
                )
            except TokenBackendError:
                raise TokenError('Token is invalid or expired')

            if self.is_verify:
                self.verify()
        else:
            self.payload = {self.settings.token_type_claim: self.token_type}
            self.set_exp(from_time=self.current_time, lifetime=self.lifetime)
            self.set_jti()

    def verify(self) -> None:
        self.check_exp()

        if self.settings.jti_claim not in self.payload:
            raise TokenError('Token has no id')

        self.verify_token_type()

    def verify_token_type(self) -> None:
        try:
            token_type = self.payload[self.settings.token_type_claim]
        except KeyError:
            raise TokenError('Token has no type')
        if self.token_type != token_type:
            raise TokenError('Token has wrong type')

    def set_exp(self, claim='exp', from_time=None, lifetime=None) -> None:
        if not from_time:
            from_time = self.current_time

        if not lifetime:
            lifetime = self.lifetime

        self.payload[claim] = datetime_to_epoch(from_time + lifetime)

    def check_exp(self, claim='exp', current_time=None) -> None:
        if not current_time:
            current_time = self.current_time
        try:
            claim_value = self.payload[claim]
        except KeyError:
            raise TokenError(f"Token has no '{claim}' claim")
        claim_time = datetime_from_epoch(claim_value)
        if claim_time <= current_time:
            raise TokenError(f"Token '{claim}' claim has expired")

    def set_jti(self) -> None:
        self.payload[self.settings.jti_claim] = uuid4().hex

    @classmethod
    def for_user(cls, settings: JwtSettings, user: Any):
        token = cls(settings)
        user_id = getattr(user, settings.user_id_field)
        if not isinstance(user_id, int):
            user_id = str(user_id)
        token[settings.user_id_claim] = user_id
        return token

    def __repr__(self) -> str:
        return repr(self.payload)

    def __getitem__(self, key) -> Any:
        return self.payload[key]

    def __setitem__(self, key, value) -> None:
        self.payload[key] = value

    def __delitem__(self, key) -> None:
        del self.payload[key]

    def __contains__(self, key) -> bool:
        return key in self.payload

    def __str__(self) -> str:
        return self.token_backend.encode(self.payload)

    def get(self, key, default=None) -> Any:
        return self.payload.get(key, default)


@attr.s
class AccessToken(Token):
    token_type: str = 'access'
    lifetime: timedelta = attr.ib(
        init=False,
        default=attr.Factory(
            lambda self: self.settings.access_token_lifetime,
            takes_self=True,
        ),
        converter=to_timedelta,
        validator=instance_of(timedelta),
    )


@attr.s
class RefreshToken(Token):
    token_type: str = 'refresh'
    lifetime: timedelta = attr.ib(
        init=False,
        default=attr.Factory(
            lambda self: self.settings.refresh_token_lifetime,
            takes_self=True,
        ),
        converter=to_timedelta,
        validator=instance_of(timedelta),
    )

    @property
    def access_token(self):
        access = AccessToken(self.settings)
        access.set_exp(from_time=self.current_time)
        no_copy_claims = (
            'jti',
            'exp',
            self.settings.jti_claim,
            self.settings.token_type_claim,
        )

        for claim, value in self.payload.items():
            if claim in no_copy_claims:
                continue
            access[claim] = value

        return access
