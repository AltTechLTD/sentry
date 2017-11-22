from __future__ import absolute_import

import ipaddress
import logging
import six

from datetime import datetime, timedelta
from django.conf import settings
from django.core.signing import BadSignature
from django.utils import timezone
from django.utils.crypto import constant_time_compare, get_random_string

logger = logging.getLogger('sentry.superuser')

SESSION_KEY = '_su'

COOKIE_NAME = getattr(settings, 'SUPERUSER_COOKIE_NAME', 'su')

COOKIE_SALT = getattr(settings, 'SUPERUSER_COOKIE_SALT', '')

COOKIE_SECURE = getattr(settings, 'SUPERUSER_COOKIE_SECURE', settings.SESSION_COOKIE_SECURE)

COOKIE_DOMAIN = getattr(settings, 'SUPERUSER_COOKIE_DOMAIN', settings.SESSION_COOKIE_DOMAIN)

COOKIE_PATH = getattr(settings, 'SUPERUSER_COOKIE_PATH', settings.SESSION_COOKIE_PATH)

# the maximum time the cookie can stay alive
COOKIE_MAX_AGE = getattr(settings, 'SUPERUSER_COOKIE_MAX_AGE', timedelta(hours=6))

# the maximum time the cookie can stay alive
# without making another request
COOKIE_IDLE_AGE = getattr(settings, 'SUPERUSER_COOKIE_IDLE_AGE', timedelta(minutes=15))

COOKIE_HTTPONLY = getattr(settings, 'SUPERUSER_COOKIE_HTTPONLY', True)

ALLOWED_IPS = frozenset(getattr(settings, 'SUPERUSER_ALLOWED_IPS', settings.INTERNAL_IPS) or ())

UNSET = object()


def is_active_superuser(request):
    su = getattr(request, 'superuser', None) or Superuser(request)
    return su.is_active


class Superuser(object):
    allowed_ips = [
        ipaddress.ip_network(six.text_type(v), strict=False) for v in ALLOWED_IPS
    ]

    def __init__(self, request, allowed_ips=UNSET, current_datetime=None):
        self.request = request
        if allowed_ips is not UNSET:
            self.allowed_ips = frozenset(
                ipaddress.ip_network(six.text_type(v), strict=False) for v in allowed_ips or ()
            )
        self.populate(current_datetime=current_datetime)

    def is_privileged_request(self):
        allowed_ips = self.allowed_ips
        # if there's no IPs configured, we allow assume its the same as *
        if not allowed_ips:
            return True
        ip = self.request.META['REMOTE_ADDR']
        if not any(ip in addr for addr in allowed_ips):
            return False
        return True

    def get_session_data(self, current_datetime=None):
        request = self.request
        data = request.session.get(SESSION_KEY)
        if not data:
            logger.warn('superuser.missing-session-data', extra={
                'ip_address': request.META['REMOTE_ADDR'],
                'user_id': request.user.id,
            })
            return

        try:
            cookie_token = request.get_signed_cookie(
                key=COOKIE_NAME,
                default=None,
                salt=COOKIE_SALT,
                max_age=COOKIE_MAX_AGE.total_seconds()
            )
            if not cookie_token:
                return
        except BadSignature:
            logger.exception('superuser.bad-cookie-signature', extra={
                'ip_address': request.META['REMOTE_ADDR'],
                'user_id': request.user.id,
            })
            return

        if not self.is_valid_token(cookie_token, data, current_datetime=current_datetime):
            return

        return data

    def is_valid_data(self, cookie_token, data, current_datetime=None):
        request = self.request

        if not cookie_token:
            logger.warn('superuser.missing-cookie-token', extra={
                'ip_address': request.META['REMOTE_ADDR'],
                'user_id': request.user.id,
            })
            return False

        session_token = data.get('tok')
        if not session_token:
            logger.warn('superuser.missing-session-token', extra={
                'ip_address': request.META['REMOTE_ADDR'],
                'user_id': request.user.id,
            })
            return False

        if not constant_time_compare(cookie_token, session_token):
            logger.warn('superuser.invalid-token', extra={
                'ip_address': request.META['REMOTE_ADDR'],
                'user_id': request.user.id,
            })
            return False

        if data['uid'] != request.user.id:
            logger.warn('superuser.invalid-uid', extra={
                'ip_address': request.META['REMOTE_ADDR'],
                'user_id': request.user.id,
                'expected_user_id': data['uid'],
            })
            return False

        if current_datetime is None:
            current_datetime = timezone.now()

        try:
            if datetime.utcfromtimestamp(data['idl']).replace(
                    tzinfo=timezone.utc) < current_datetime:
                logger.info('superuser.session-expired', extra={
                    'ip_address': request.META['REMOTE_ADDR'],
                    'user_id': request.user.id,
                })
                return False
        except (TypeError, ValueError):
            logger.warn('superuser.invalid-idle-expiration', extra={
                'ip_address': request.META['REMOTE_ADDR'],
                'user_id': request.user.id,
            })
            return False

        if data['exp'] < current_datetime:
            logger.info('superuser.session-expired', extra={
                'ip_address': request.META['REMOTE_ADDR'],
                'user_id': request.user.id,
            })
            return False

        return True

    def populate(self, current_datetime=None):
        if current_datetime is None:
            current_datetime = timezone.now()

        request = self.request
        user = getattr(request, 'user', None)
        if not hasattr(request, 'session'):
            data = None
        elif not (user and user.is_superuser):
            data = None
        else:
            data = self.get_session_data(current_datetime=current_datetime)

        if not data:
            self._set_logged_out()
        else:
            self._set_logged_in(
                expires=datetime.utcfromtimestmap(data['exp'], tzinfo=timezone.utc),
                token=data['tok'],
                user=user,
            )

            if not self.active:
                logger.warn('superuser.invalid-ip', extra={
                    'ip_address': request.META['REMOTE_ADDR'],
                    'user_id': request.user.id,
                })

    def _set_logged_in(self, expires, token, user, current_datetime=None):
        # we bind uid here, as if you change users in the same request
        # we wouldn't want to still support superuser auth (given
        # the superuser check happens right here)
        assert user.is_superuser
        if current_datetime is None:
            current_datetime = timezone.now()
        self.uid = user.id
        self.expires = expires
        self.token = token
        self.is_active = self.is_privileged_request()
        self.request.session[SESSION_KEY] = {
            'exp': self.expires,
            'idl': (current_datetime + COOKIE_IDLE_AGE).strftime('%s'),
            'tok': self.token,
            # XXX(dcramer): do we really need the uid safety m echanism
            'uid': self.uid,
        }

    def _set_logged_out(self):
        self.uid = None
        self.expires = None
        self.token = None
        self.is_active = False
        self.request.session.pop(SESSION_KEY, None)

    def set_logged_in(self, user, current_datetime=None):
        request = self.request
        if current_datetime is None:
            current_datetime = timezone.now()
        self._set_logged_in(
            expires=current_datetime + COOKIE_MAX_AGE,
            token=get_random_string(12),
            user=user,
            current_datetime=current_datetime,
        )
        logger.info('superuser.logged-in', extra={
            'ip_address': request.META['REMOTE_ADDR'],
            'user_id': user.id,
        })

    def set_logged_out(self):
        request = self.request
        self._set_logged_out()
        logger.info('superuser.logged-out', extra={
            'ip_address': request.META['REMOTE_ADDR'],
            'user_id': request.user.id,
        })

    def on_response(self, response, current_datetime=None):
        request = self.request

        if current_datetime is None:
            current_datetime = timezone.now()

        # always re-bind the cookie to update the idle expiration window
        if self.is_active:
            response.set_signed_cookie(
                COOKIE_NAME,
                self.token,
                salt=COOKIE_SALT,
                # set max_age to None, as we want this cookie to expire on browser close
                max_age=None,
                secure=request.is_secure() if COOKIE_SECURE is None else COOKIE_SECURE,
                httponly=COOKIE_HTTPONLY,
                path=COOKIE_PATH,
                domain=COOKIE_DOMAIN,
            )
        elif request.COOKIES.get(COOKIE_NAME):
            response.delete_cookie(COOKIE_NAME)
