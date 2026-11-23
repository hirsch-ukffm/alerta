import base64
import re
from functools import wraps
from typing import TYPE_CHECKING

import mohawk
from flask import current_app, g, request
from jwt import DecodeError, ExpiredSignatureError, InvalidAudienceError

from alerta.auth.hmac import HmacAuth
from alerta.auth.utils import get_customers, not_authorized
from alerta.exceptions import ApiError, BasicAuthError
from alerta.models.enums import ADMIN_SCOPES
from alerta.models.key import ApiKey
from alerta.models.permission import Permission
from alerta.models.token import Jwt
from alerta.models.user import User
from alerta.utils.audit import auth_audit_trail

if TYPE_CHECKING:
    from typing import List  # noqa

    from alerta.models.enums import Scope  # noqa


def permission(scope=None):
    def decorated(f):
        @wraps(f)
        def wrapped(*args, **kwargs):

            auth_header = request.headers.get('Authorization', '')

            # API Key (Authorization: Key <key>)
            if 'Authorization' in request.headers and auth_header.startswith('Key '):
                m = re.match(r'Key (\S+)', auth_header)
                key = m.group(1) if m else None
            # API Key (X-API-Key: <key>)
            elif 'X-API-Key' in request.headers:
                key = request.headers['X-API-Key']
            # API Key (/foo?api-key=<key>)
            else:
                key = request.args.get('api-key', None)

            if key:
                key_info = ApiKey.verify_key(key)
                if not key_info:
                    auth_audit_trail.send(current_app._get_current_object(), event='api-key-invalid',
                                          message='API request without valid API key', user=None, customers=[], scopes=[],
                                          resource_id=key, type='apikey', request=request)
                    raise ApiError(f"API key parameter '{key}' is invalid", 401)
                g.user_id = None
                g.login = key_info.user
                g.customers = [key_info.customer] if key_info.customer else []
                g.scopes = key_info.scopes  # type: List[Scope]

                if not Permission.is_in_scope(scope, have_scopes=g.scopes):
                    auth_audit_trail.send(current_app._get_current_object(), event='api-key-scope-violation',
                                          message='API request outside of scope', user=g.login, customers=g.customers, scopes=g.scopes,
                                          resource_id=key, type='apikey', request=request)
                    raise ApiError(f'Missing required scope: {scope}', 403)
                else:
                    return f(*args, **kwargs)

            # Hawk HMAC Signature (Authorization: Hawk mac=...)
            if auth_header.startswith('Hawk'):
                try:
                    receiver = HmacAuth.authenticate(request)
                except mohawk.exc.HawkFail as e:
                    auth_audit_trail.send(current_app._get_current_object(), event='hawk-fail',
                                          message='API request with invalid Hawk HMAC', user=None, customers=[], scopes=[],
                                          resource_id=auth_header, type='auth', request=request, exception=e)
                    raise ApiError(str(e), 401)

                g.user_id = None
                g.login = receiver.parsed_header.get('id')
                g.customers = []
                g.scopes = ADMIN_SCOPES
                return f(*args, **kwargs)

            # Bearer Token
            m = re.match(r'Bearer (\S+)', auth_header)
            token = m.group(1) if m else None

            if token:
                try:
                    jwt = Jwt.parse(token)
                except DecodeError:
                    auth_audit_trail.send(current_app._get_current_object(), event='bearer-invalid-audience',
                                          message='API request with invalid bearer token', user=None, customers=[], scopes=[],
                                          resource_id=token, type='bearer-token', request=request)
                    raise ApiError('Token is invalid', 401)
                except ExpiredSignatureError:
                    auth_audit_trail.send(current_app._get_current_object(), event='bearer-expired',
                                          message='API request with expired bearer token', user=None, customers=[], scopes=[],
                                          resource_id=token, type='bearer-token', request=request)
                    raise ApiError('Token has expired', 401)
                except InvalidAudienceError:
                    auth_audit_trail.send(current_app._get_current_object(), event='bearer-invalid-audience',
                                          message='API request with bearer token has invalid audience', user=None, customers=[], scopes=[],
                                          resource_id=token, type='bearer-token', request=request)
                    raise ApiError('Invalid audience', 401)
                g.user_id = jwt.oid or jwt.subject
                g.login = jwt.preferred_username
                g.customers = jwt.customers
                g.scopes = jwt.scopes  # type: List[Scope]

                if not Permission.is_in_scope(scope, have_scopes=g.scopes):
                    auth_audit_trail.send(current_app._get_current_object(), event='bearer-scope-violation',
                                          message='API request outside of scope', user=g.login, customers=g.customers, scopes=g.scopes,
                                          resource_id=token, type='bearer-token', request=request)
                    raise ApiError(f'Missing required scope: {scope}', 403)
                else:
                    return f(*args, **kwargs)

            # AuthProxy
            proxy_user_header = current_app.config['AUTH_PROXY_USER_HEADER']
            proxy_roles_header = current_app.config['AUTH_PROXY_ROLES_HEADER']
            proxy_roles_header_sep = current_app.config['AUTH_PROXY_ROLES_SEPARATOR']

            if current_app.config['AUTH_PROXY'] and proxy_user_header in request.headers:
                username = request.headers[proxy_user_header]
                roles = request.headers.get(proxy_roles_header, '').split(proxy_roles_header_sep)

                user = User.find_by_username(username)

                if not user:
                    if current_app.config['AUTH_PROXY_AUTO_SIGNUP']:
                        try:
                            user = User(name=username, login=username, password='', email='', roles=roles, text='Proxy user')
                            user = user.create()
                        except Exception as e:
                            auth_audit_trail.send(current_app._get_current_object(), event='auth-proxy-user-creation-failure',
                                                  message='API request with new AuthProxy user failed', user=g.login, customers=g.customers, scopes=g.scopes,
                                                  resource_id=username, type='username', request=request, error=str(e))
                            ApiError(str(e), 500)
                    else:
                        auth_audit_trail.send(current_app._get_current_object(), event='auth-proxy-user-creation-denied',
                                              message='API request with new AuthProxy user denied', user=g.login, customers=g.customers, scopes=g.scopes,
                                              resource_id=username, type='username', request=request)
                        raise ApiError('user auto-signup is disabled', 403)

                g.user_id = user.id
                g.login = user.login
                g.customers = get_customers(user.login, groups=user.get_groups())
                g.scopes = Permission.lookup(user.login, roles=roles)  # type: List[Scope]

                if not Permission.is_in_scope(scope, have_scopes=g.scopes):
                    auth_audit_trail.send(current_app._get_current_object(), event='auth-proxy-scope-violation',
                                          message='API request outside of scope', user=g.login, customers=g.customers, scopes=g.scopes,
                                          resource_id=username, type='username', request=request)
                    raise BasicAuthError(f'Missing required scope: {scope}', 403)
                else:
                    return f(*args, **kwargs)

            # Basic Auth
            m = re.match(r'Basic (\S+)', auth_header)
            credentials = m.group(1) if m else None

            if credentials:
                decoded_credentials = None
                try:
                    decoded_credentials = base64.b64decode(credentials).decode('utf-8')
                    username, password = decoded_credentials.split(':', maxsplit=1)
                except Exception as e:
                    auth_audit_trail.send(current_app._get_current_object(), event='basic-auth-decode-failure',
                                          message='API request with invalid basic authentication', user=g.login, customers=g.customers, scopes=g.scopes,
                                          resource_id=decoded_credentials or credentials, type='credentials', request=request)
                    raise BasicAuthError('Invalid credentials', 400, errors=[str(e)])

                user = User.check_credentials(username, password)
                if not user:
                    auth_audit_trail.send(current_app._get_current_object(), event='basic-auth-failure',
                                          message='API request with invalid credentials', user=g.login, customers=g.customers, scopes=g.scopes,
                                          resource_id=decoded_credentials, type='credentials', request=request)
                    raise BasicAuthError('Authorization required', 401)

                if current_app.config['EMAIL_VERIFICATION'] and not user.email_verified:
                    auth_audit_trail.send(current_app._get_current_object(), event='basic-auth-email-not-verified',
                                          message='API request with unverified email', user=g.login, customers=g.customers, scopes=g.scopes,
                                          resource_id=decoded_credentials, type='credentials', request=request)
                    raise BasicAuthError('email not verified', 401)

                if not_authorized('ALLOWED_EMAIL_DOMAINS', groups=[user.domain]):
                    auth_audit_trail.send(current_app._get_current_object(), event='basic-auth-email-unauthorized-domain',
                                          message='API request with email on unauthorized domain', user=g.login, customers=g.customers, scopes=g.scopes,
                                          resource_id=decoded_credentials, type='credentials', request=request)
                    raise BasicAuthError('Unauthorized domain', 403)

                g.user_id = user.id
                g.login = user.email
                g.customers = get_customers(user.email, groups=[user.domain])
                g.scopes = Permission.lookup(user.email, roles=user.roles)  # type: List[Scope]

                if not Permission.is_in_scope(scope, have_scopes=g.scopes):
                    auth_audit_trail.send(current_app._get_current_object(), event='basic-auth-scope-violation',
                                          message='API request outside of scope', user=g.login, customers=g.customers, scopes=g.scopes,
                                          resource_id=decoded_credentials, type='credentials', request=request)
                    raise BasicAuthError(f'Missing required scope: {scope}', 403)
                else:
                    return f(*args, **kwargs)

            # auth not required
            if not current_app.config['AUTH_REQUIRED']:
                g.user_id = None
                g.login = None
                g.customers = []
                g.scopes = []  # type: List[Scope]
                return f(*args, **kwargs)

            # auth required for admin/write, but readonly is allowed
            if current_app.config['AUTH_REQUIRED'] and current_app.config['ALLOW_READONLY']:
                g.user_id = None
                g.login = None
                g.customers = []
                g.scopes = current_app.config['READONLY_SCOPES']
                return f(*args, **kwargs)

            # Google App Engine Cron Service
            if request.headers.get('X-Appengine-Cron', False) and request.headers.get('X-Forwarded-For', '') == '0.1.0.1':
                return f(*args, **kwargs)

            auth_audit_trail.send(current_app._get_current_object(), event='missing-authorization',
                                  message='API request is missing authorization', user=g.login, customers=g.customers, scopes=g.scopes,
                                  resource_id='', type='', request=request)

            raise ApiError('Missing authorization API Key or Bearer Token', 401)

        return wrapped
    return decorated
