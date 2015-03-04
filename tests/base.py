# -*- coding: utf-8 -*-

import os
import unittest

import koji
import koji.auth
import kojihub as hub
from koji.context import context
from koji import db


__all__ = ('TestCase',)


class AuthMixin(object):
    """Test Auth mixin"""

    sample_perms = ('admin',
                    'build',
                    'repo',
                    'livecd',
                    'maven-import',
                    'win-import',
                    'win-admin',
                    'appliance',
                    )

    def auth_setUp(self):
        self.user_name = 'koji_tester'
        # It doesn't matter from where the Session object comes. createUser
        # only needs one. This line of code here just aims to create an user,
        # that's it.
        self.user_id = koji.auth.Session().createUser(self.user_name)

        self.initialize_perms()

    def initialize_perms(self):
        """Initialize permissions for test"""
        sql_add_perm = 'INSERT INTO permissions (name) VALUES (%(perm)s)'
        # Duplicated permissions are not allowed to add, because current test
        # database used by developer running unit tests might have those added
        # already.
        sql_find_perm = 'SELECT 1 FROM permissions WHERE name = %(perm)s'
        self._added_perms = []
        for perm in self.sample_perms:
            values = {'perm': perm}
            # When run tests with real koji db, this if statement is necessary
            # to avoid duplicated permission name to add
            if db.fetchSingle(sql_find_perm, values) is None:
                db.dml(sql_add_perm, values)
                self._added_perms.append(perm)

    def auth_tearDown(self):
        perms = getattr(self, '_added_perms', None)
        if perms:
            sql = 'DELETE FROM permissions WHERE name IN %(perms)s'
            db.dml(sql, {'perms': perms})

        self.delete_user(self.user_id)

    def make_me_as_admin(self, session=None):
        """Patch hasPerm to make it return True always when admin is checked"""
        if session is None:
            session = self.test_session
        self._origin_assertPerm = session.assertPerm
        session.assertPerm = self._patch_assertPerm

    def _patch_assertPerm(self, name):
        """Patch method for return True always when admin is checked"""
        if name == 'admin':
            return True
        else:
            return self._origin_assertPerm(name)

    def grant_permissions(self, user_id, *perms):
        """Grant one or more permissions to an user"""
        sql = 'INSERT INTO user_perms (user_id, perm_id, creator_id) ' \
              'VALUES (%(user_id)i, %(perm_id)i, %(creator_id)i)'
        values = {'user_id': user_id,
                  'perm_id': None,
                  'creator_id': self.user_id
                  }
        for perm in perms:
            values['perm_id'] = self.perm_id_by_name(perm)
            db.dml(sql, values)

    def revoke_permissions(self, user_id, *perms):
        """Revoke permissions from an user"""
        sql = '''
UPDATE user_perms SET
  revoke_event = %(revoke_event)i,
  revoker_id = %(revoker_id)i,
  active = null
WHERE user_id = %(user_id)i AND perm_id = %(perm_id)i AND active = true'''
        values = {'user_id': user_id,
                  'perm_id': None,
                  'revoker_id': self.user_id,
                  'revoke_event': hub.get_event(),
                  }
        for perm in perms:
            values['perm_id'] = self.perm_id_by_name(perm)
            db.dml(sql, values)

    def remove_granted_permissions(self, user_id, *perms):
        sql = '''
DELETE FROM user_perms
WHERE user_id = %(user_id)i AND perm_id = %(perm_id)i AND active = true'''
        values = {'user_id': user_id, 'perm_id': None}
        for perm in perms:
            values['perm_id'] = self.perm_id_by_name(perm)
            db.dml(sql, values)

    def perm_id_by_name(self, perm):
        """Get permission id from name"""
        sql = 'SELECT id FROM permissions WHERE name = %(perm)s'
        return db.singleValue(sql, {'perm': perm})

    def delete_user(self, user_info):
        """Delete arbitrary type of user by either id or name"""
        if isinstance(user_info, basestring):
            db.dml('DELETE FROM users WHERE name = %(user_info)s', locals())
        else:
            db.dml('DELETE FROM users WHERE id = %(user_info)i', locals())

    def delete_session(self, session_id):
        sql = 'DELETE FROM sessions WHERE id = %(session_id)s'
        db.dml(sql, locals())


class SessionMixin(object):
    """Test Session"""

    def session_setUp(self):
        self.global_context.session = self.new_session()

        dbname = os.environ.get('koji.test.database', 'koji_test')
        user = os.environ.get('koji.test.user', 'koji')
        password = os.environ.get('koji.test.password', 'koji')
        host = os.environ.get('koji.test.host', '127.0.0.1')

        koji.db.setDBopts(database=dbname, user=user,
                          password=password, host=host)
        context.cnx = koji.db.connect()

    def session_tearDown(self):
        context.cnx.close()
        context._threadclear()

    def new_session(self, args=None, hostip=None):
        if hostip is None:
            hostip = os.environ.get('koji.test.session_hostip', '127.0.0.1')
        return koji.auth.Session(args, hostip=hostip)

    def get_session(self, session_id):
        fields = ('id', 'user_id', 'expired', 'master', 'key', 'authtype',
                  'hostip', 'callnum', 'start_time', 'update_time',
                  'exclusive')
        sql = 'SELECT %s FROM sessions WHERE id = %%(sid)i' % \
            ', '.join(fields)
        return db.singleRow(sql, {'sid': session_id}, fields)

    @property
    def global_context(self):
        return context

    @property
    def test_session(self):
        try:
            return self.global_context.session
        except NameError:
            raise NameError, 'A session should be initialized in advance.'

    def make_me_logged_in(self, session=None):
        """Make a session logged-in

        session: an instance of koji.auth.Session. That is patched to be
        logged-in. If not supplied, the default test_session will be patched.
        """
        _session = session
        if session is None:
            _session = self.test_session
        _session.logged_in = True
        _session.user_id = self.user_id

    def create_normal_user(self, name=None, status=None, usertype=None):
        """Create a normal user"""
        sql = '''
INSERT INTO users (id, name, status, usertype)
VALUES (%(user_id)i, %(name)s, %(status)i, %(usertype)i)'''
        if name is None:
            name = 'koji_tester'
        if status is None:
            status = koji.USER_STATUS['NORMAL']
        if usertype is None:
            usertype = koji.USERTYPES['NORMAL']
        user_id = db.get_sequence_nextval('users_id_seq')
        db.dml(sql, locals())
        return user_id

    def delete_user_sessions(self, user_id):
        """Delete a specific user's sessions"""
        sql = 'DELETE FROM sessions WHERE user_id = %(user_id)i'
        db.dml(sql, locals())

    def mock_environ(self, vars=None):
        """Mock environ with basic variables against global context"""
        _vars = {'wsgi.url_scheme': 'http',
                'REMOTE_ADDR': '127.0.0.1',
                }
        if vars is not None:
            _vars.update(vars)
        environ = getattr(self.global_context, 'environ', None)
        if environ is None:
            self.global_context.environ = _vars
        else:
            environ.update(_vars)

    def mock_environ_over_ssl(self, user_name=None):
        """Mock valid environ variables for SSL"""
        vars = {'wsgi.url_scheme': 'https',
                'SSL_CLIENT_VERIFY': 'SUCCESS',
                'SSL_CLIENT_S_DN_CN': user_name,
                }
        # Patch session to add an empty environ
        self.mock_environ(vars)


class TestCase(SessionMixin, AuthMixin, unittest.TestCase):
    """Base koji TestCase

    TestCase provides basic mechanism to write a TestCase. Writing a new
    TestCase is simple just by inheriting from TesCase, then you have the
    connection to database, a context accessible globally, and an
    incomplete-initialized session.

    An incomplete-initialized session means that a session is initiated without
    a valid argument `args`. Without the argument `args`, a session instance is
    able to do many things, for exmaple `createUser`. However, if you need a
    complete session, method `new_session` can be used to create one by
    yourself.

    Reading TestCases is the right way to know quickly how to use existent
    utility methods to bring convenience.
    """

    def setUp(self):
        self.session_setUp()
        self.auth_setUp()

    def tearDown(self):
        self.auth_tearDown()
        self.session_tearDown()
