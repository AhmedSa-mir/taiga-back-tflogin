import requests
import os
import json
from urllib.parse import urlencode
from uuid import uuid4

from django.conf import settings
from django.shortcuts import redirect
from django.http import JsonResponse

from taiga.base import response
from taiga.base import exceptions as exc

from .services import public_register
from .services import is_user_already_registered
from .services import get_auth_plugins

OAUTH_URL = "https://oauth.threefold.io"
REDIRECT_URL = "https://login.threefold.me"


def tf_login(request):
    # state = str(uuid4()).replace("-", "")
    # request.session["state"] = state
    state="1234567"

    response = requests.get(f"{OAUTH_URL}/pubkey")
    response.raise_for_status()
    data = response.json()

    params = {
        "state": state,
        "appid": settings.SITES["api"]["domain"],
        "scope": json.dumps({"user": True, "email": True}),
        "redirecturl": "/api/v1/threebot/callback",
        "publickey": data["publickey"].encode(),
    }
    params = urlencode(params)
    return redirect(f"{REDIRECT_URL}?{params}")

def tf_callback(request):
    data = request.GET.get('signedAttempt')
    # resp = requests.post(f"{OAUTH_URL}/verify", data={"signedAttempt": data, "state": request.session.get("state")})
    resp = requests.post(f"{OAUTH_URL}/verify", data={"signedAttempt": data, "state": "1234567"})
    resp.raise_for_status()
    data = resp.json()
    username = data['username']
    email = data['email']

    # registeration
    is_registered, _ = is_user_already_registered(username=username, email=email)
    if not is_registered:
        public_register(username=username, password=email, email=email, full_name=username)

    # login
    auth_plugins = get_auth_plugins()

    request.DATA = {'username': username, 'password': email}

    login_type = request.GET.get("type", "normal")
    if login_type in auth_plugins:
        data = auth_plugins[login_type]['login_func'](request)
        data['roles'] = list(data['roles'].values())    # roles is a QuerySet which is not JSON serializable
        params = urlencode(data)
        # TODO: https
        return redirect(f"http://{settings.SITES['api']['domain']}/login?{params}")

    raise exc.BadRequest(_("invalid login type"))
