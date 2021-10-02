from blacksheep import Content
from blacksheep import Request
from blacksheep import Response
from blacksheep.server import Application
from blacksheep_jwt.authentication import JwtAuthentication
from blacksheep_jwt.errors import InvalidToken
from blacksheep_jwt.settings import JwtSettings
from guardpost.common import AuthenticatedRequirement
from guardpost.common import Policy

try:
    import orjson as json
except ImportError:
    import json  # type: ignore


def register_jwt(
    app: Application,
    settings: dict,
    add_exception_handlers: bool = False,
):
    jwt_settings = JwtSettings(**settings)
    app.services.add_instance(jwt_settings)
    app.use_authentication().add(JwtAuthentication(jwt_settings))
    app.use_authorization().add(
        Policy('authenticated', AuthenticatedRequirement()),
    )
    if add_exception_handlers:

        @app.exception_handler(InvalidToken)
        async def invalid_token(
            self,
            request: Request,
            exc: InvalidToken,
        ):
            return Response(
                401,
                None,
                Content(
                    b'application/json',
                    json.dumps(str(exc)),
                ),
            )
