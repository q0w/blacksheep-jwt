from typing import Optional

from blacksheep import Request
from blacksheep_jwt.errors import InvalidToken
from blacksheep_jwt.errors import TokenError
from blacksheep_jwt.settings import JwtSettings
from blacksheep_jwt.utils import import_string
from guardpost.asynchronous.authentication import AuthenticationHandler
from guardpost.authentication import Identity
from guardpost.authentication import User


class JwtAuthentication(AuthenticationHandler):
    def __init__(
        self,
        settings: JwtSettings,
    ):
        self.settings = settings

    async def authenticate(self, context: Request) -> Optional[Identity]:
        authorization_value = context.get_first_header(
            self.settings.auth_header_name,
        )

        if not authorization_value:
            context.identity = User({})
            return None

        if (
            not authorization_value.split()[0]
            == self.settings.auth_header_type
        ):
            context.identity = User({})
            return None

        token = authorization_value.split()[1].decode()
        try:
            for AuthToken in self.settings.auth_token_classes:
                decoded = import_string(AuthToken)(
                    token=token,
                    settings=self.settings,
                ).payload
        except TokenError as e:
            # TODO: catch errors
            # TODO: support more than one auth method
            raise InvalidToken(str(e)) from None
        else:
            context.identity = User(
                decoded,
                self.settings.auth_header_type.decode(),
            )
            return context.identity
