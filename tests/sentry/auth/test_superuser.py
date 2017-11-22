from __future__ import absolute_import

from sentry.models import User
from sentry.auth.superuser import Superuser
from sentry.testutils import TestCase


class SuperuserTestCase(TestCase):
    def test_ips(self):
        user = User(is_superuser=True)
        request = self.make_request(user=user)
        request.META['REMOTE_ADDR'] = '10.0.0.1'

        # no ips = any host
        superuser = Superuser(request, allowed_ips=())
        superuser.set_logged_in(request.user)
        assert superuser.is_active is True

        superuser = Superuser(request, allowed_ips=('127.0.0.1',))
        superuser.set_logged_in(request.user)
        assert superuser.is_active is False

        superuser = Superuser(request, allowed_ips=('10.0.0.1',))
        superuser.set_logged_in(request.user)
        assert superuser.is_active is True
