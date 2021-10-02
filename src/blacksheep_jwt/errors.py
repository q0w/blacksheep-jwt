from essentials.exceptions import UnauthorizedException


class TokenBackendError(Exception):
    pass


class TokenError(Exception):
    pass


class InvalidToken(UnauthorizedException):
    pass
