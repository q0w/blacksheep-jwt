from dataclasses import dataclass

from blacksheep.server import Application
from blacksheep.server.authorization import auth
from blacksheep.server.bindings import FromJson
from blacksheep.server.responses import json
from blacksheep_jwt import register_jwt
from blacksheep_jwt.settings import JwtSettings
from blacksheep_jwt.tokens import RefreshToken
from configuration.common import ConfigurationBuilder
from configuration.json import JSONFile
from guardpost import Identity

config = ConfigurationBuilder(JSONFile('settings.json')).build()
app = Application(show_error_details=True)
register_jwt(app, config.jwt.values)


@dataclass
class User:
    id: int


@app.router.get('/')
async def home() -> str:
    return 'Hello world!'


@auth('authenticated')
@app.router.get('/index')
async def index(user: Identity) -> json:
    return json(user.claims)


@app.router.post('/login')
async def login(input: FromJson[User], settings: JwtSettings):
    refresh = RefreshToken.for_user(settings, user=User(id=input.value.id))
    return json({'access': str(refresh.access_token), 'refresh': str(refresh)})


@app.router.post('/refresh')
async def refresh(body: FromJson[dict], settings: JwtSettings):
    refresh: RefreshToken = RefreshToken(
        token=body.value['refresh'],
        settings=settings,
    )
    return json({'access': str(refresh.access_token)})
