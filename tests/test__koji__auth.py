# -*- coding: utf-8 -*-

import koji
import koji.auth as auth
import koji.db as db
import kojihub as hub

from base import TestCase


class TestGetUserData(TestCase):
    """Test get_user_data"""

    def test_get_an_existing_user(self):
        """Test get an existing user"""
        user = auth.get_user_data(self.user_id)
        self.assertNotEqual(user, None)
        self.assert_('name' in user)
        self.assert_('status' in user)
        self.assert_('usertype' in user)

    def test_get_a_nonexisting_user(self):
        """Test get a nonexisiting user"""
        user = auth.get_user_data(self.user_id * 10000)
        self.assertEqual(user, None)


class TestGetUserPerms(TestCase):
    """Test get_user_perms"""

    def test_perms(self):
        """Test get permissions of an user"""
        perms = self.sample_perms[0:3]
        self.grant_permissions(self.user_id, *perms)

        try:
            user_perms = auth.get_user_perms(self.user_id)
            self.assertEqual(len(user_perms), len(perms))
            self.assertEqual(len(set(user_perms) - set(perms)), 0)
        finally:
            self.remove_granted_permissions(self.user_id, *perms)

    def test_user_has_no_perms(self):
        """Test get permissions of an user who has no permissions"""
        perms = auth.get_user_perms(self.user_id)
        self.assertEqual(len(perms), 0)

    def test_nonexistent_user(self):
        """Test get permissions from a nonexistent user"""
        perms = auth.get_user_perms(self.user_id * 10000)
        self.assertEqual(len(perms), 0)


class TestGetUserGroups(TestCase):
    """Test get_user_groups"""

    def setUp(self):
        super(TestGetUserGroups, self).setUp()

        self.make_me_as_admin()
        self.make_me_logged_in()

        createUser = self.test_session.createUser

        self.group_names = ('test_group1', 'test_group2', 'test_group3')
        self.group1_id = createUser(self.group_names[0],
                                    usertype=koji.USERTYPES['GROUP'])
        self.group2_id = createUser(self.group_names[1],
                                    usertype=koji.USERTYPES['GROUP'])
        self.group3_id = createUser(self.group_names[2],
                                    usertype=koji.USERTYPES['GROUP'])
        self.test_user_id = createUser('test_user')
        self.test_user2_id = createUser('test_user2')

        hub.add_group_member(self.group1_id, self.test_user_id)
        hub.add_group_member(self.group2_id, self.test_user_id)
        hub.add_group_member(self.group3_id, self.test_user_id)

    def tearDown(self):
        sql = '''
DELETE FROM user_groups
WHERE user_id = %(user_id)i AND group_id = %(group_id)i AND active = true'''
        db.dml(sql, {'user_id': self.test_user_id, 'group_id': self.group1_id})
        db.dml(sql, {'user_id': self.test_user_id, 'group_id': self.group2_id})
        db.dml(sql, {'user_id': self.test_user_id, 'group_id': self.group3_id})

        self.delete_user(self.test_user_id)
        self.delete_user(self.test_user2_id)
        self.delete_user(self.group1_id)
        self.delete_user(self.group2_id)
        self.delete_user(self.group3_id)

        super(TestGetUserGroups, self).tearDown()

    def test_get_groups(self):
        """Test get groups from an user"""
        groups = auth.get_user_groups(self.test_user_id)
        self.assertEqual(len(groups), 3)
        self.assertEqual(len(set(groups.values()) - set(self.group_names)), 0)

    def test_user_is_not_in_any_group(self):
        """Test get groups from user who is not in any group"""
        groups = auth.get_user_groups(self.test_user2_id)
        self.assertEqual(len(groups), 0)

    def test_nonexistent_user(self):
        """Test get groups from a nonexistent user"""
        groups = auth.get_user_groups(self.test_user2_id * 10000)
        self.assertEqual(len(groups), 0)


class TestSetKrbPrincipal(TestCase):
    """Test Session.setKrbPrincipal"""

    def setUp(self):
        super(TestSetKrbPrincipal, self).setUp()
        self.test_user_id = self.test_session.createUser('koji_test_user')

    def tearDown(self):
        self.delete_user(self.test_user_id)
        super(TestSetKrbPrincipal, self).tearDown()

    def test_update_existent_user(self):
        """Test update an existent user's krb principal"""
        user = hub.get_user(self.test_user_id)
        krb_principal = 'xxx'
        self.test_session.setKrbPrincipal(user['name'], krb_principal)

        user = hub.get_user(self.test_user_id)
        self.assertEqual(user['krb_principal'], krb_principal)

    def test_udpate_nonexsitent_user(self):
        """Test update a nonexistent user's krb principal"""
        self.assertRaises(koji.AuthError, self.test_session.setKrbPrincipal,
                          'koji X-man', 'xxx')


class TestCreateUser(TestCase):
    """Test Session.createUser"""

    def setUp(self):
        super(TestCreateUser, self).setUp()
        self.user_name = 'koji_test_user'

    def tearDown(self):
        self.delete_user(self.user_name)
        super(TestCreateUser, self).tearDown()

    def test_create_a_normal_user(self):
        """Test create a normal user"""
        user_id = self.test_session.createUser(self.user_name)
        self.assert_(user_id > 0)

        user = hub.get_user(user_id)
        self.assertEqual(user['name'], self.user_name)

    def test_another_user_with_different_status_type(self):
        """Test another user with different status and type"""
        status = koji.USER_STATUS['BLOCKED']
        usertype = koji.USERTYPES['HOST']
        user_id = self.test_session.createUser(self.user_name,
                                               status=status,
                                               usertype=usertype)
        self.assert_(user_id > 0)

        user = hub.get_user(user_id)
        self.assertEqual(user['name'], self.user_name)
        self.assertEqual(user['status'], status)
        self.assertEqual(user['usertype'], usertype)

    def test_create_a_normal_krb_user(self):
        """Test create a normal user with Kerberos principal"""
        krb_principal = 'xxx'
        user_id = self.test_session.createUser(self.user_name,
                                               krb_principal=krb_principal)
        self.assert_(user_id > 0)

        user = hub.get_user(user_id)
        self.assertEqual(user['name'], self.user_name)
        self.assertEqual(user['krb_principal'], krb_principal)


class TestCreateUserFromKerberos(TestCase):
    """Test Session.createUserFromKerberos"""

    def setUp(self):
        super(TestCreateUserFromKerberos, self).setUp()

        self.krb_principal = 'koji_test_user@REALM'
        self.another_user_name = 'another_test_user'
        self.test_user_id = self.test_session.createUser(self.another_user_name)
        self.another_krb_principal = '%s@REALM' % self.another_user_name

    def tearDown(self):
        self.delete_user(self.krb_principal.split('@')[0])
        self.delete_user(self.another_user_name)
        super(TestCreateUserFromKerberos, self).tearDown()

    def test_invalid_kerberos_principal(self):
        """Test create user from Kerberos with invalid principal"""
        self.assertRaises(koji.AuthError,
                          self.test_session.createUserFromKerberos, 'xxx')

    def test_create_a_new_user_from_principal(self):
        """Test create a new user from Kerberos principal"""
        user_id = self.test_session.createUserFromKerberos(self.krb_principal)
        self.assert_(user_id > 0)

        user = hub.get_user(user_id)
        expect_name = self.krb_principal.split('@')[0]
        self.assertEqual(user['name'], expect_name)
        self.assertEqual(user['krb_principal'], self.krb_principal)

    def test_update_an_existent_user_principal_when_create(self):
        """Test update user's principal if existent when create"""
        user_id = self.test_session.createUserFromKerberos(
            self.another_krb_principal)
        self.assertEqual(user_id, self.test_user_id)

        user = hub.get_user(user_id)
        self.assertEqual(user['krb_principal'], self.another_krb_principal)


class TestGetUserIdFromKerberos(TestCase):
    """Test getUserIdFromKerberos"""

    def setUp(self):
        super(TestGetUserIdFromKerberos, self).setUp()

        self.user_name = 'koji_test_user'
        self.krb_principal = '%s@REALME' % self.user_name
        self.test_user_id = self.test_session.createUser(
            self.user_name, krb_principal=self.krb_principal)

    def tearDown(self):
        self.delete_user(self.user_name)
        super(TestGetUserIdFromKerberos, self).tearDown()

    def test_get_user_id(self):
        """Test get user id from Kerberos principal"""
        user_id = self.test_session.getUserIdFromKerberos(self.krb_principal)
        self.assert_(user_id > 0)

        user = hub.get_user(user_id)
        self.assertEqual(user['krb_principal'], self.krb_principal)

    def test_get_nonexistent_user_id(self):
        """Test get user id from nonexistent Kerberos principal"""
        user_id = self.test_session.getUserIdFromKerberos('xxx')
        self.assertEqual(user_id, None)


class TestGetHostId(TestCase):
    """Test Session._getHostId"""

    def setUp(self):
        super(TestGetHostId, self).setUp()

        self.make_me_as_admin()
        self.root_exports = hub.RootExports()
        self.hosts = [[None, 'host1.example.com', 'x86_64', 'host1@REALM'],
                      [None, 'host2.example.com', 'i386', 'host2@REALM'],
                      [None, 'host3.example.com', 'ppcle64', 'host3@REALM']]
        for host_info in self.hosts:
            dummy, hostname, arches, principal = host_info
            host_info[0] = self.root_exports.addHost(hostname,
                                                     arches,
                                                     principal)

    def tearDown(self):
        host_ids = [item[0] for item in self.hosts]

        # Delete from host_channels
        channel_id = hub.get_channel('default')['id']
        sql = 'DELETE FROM host_channels ' \
              'WHERE host_id = %(host_id)i AND channel_id = %(channel_id)i'
        for host_id in host_ids:
            db.dml(sql, {'host_id': host_id, 'channel_id': channel_id})

        # Delete from hosts
        sql = 'SELECT user_id FROM host WHERE id IN %(host_ids)s'
        values = {'host_ids': host_ids}
        user_ids = [row[0] for row in db.fetchMulti(sql, values)]

        sql = 'DELETE FROM host WHERE id IN %(ids)s'
        db.dml(sql, {'ids': host_ids})

        # Delete from users whose usertype is Host
        sql = 'DELETE FROM users WHERE id IN %(ids)s'
        db.dml(sql, {'ids': user_ids})

        super(TestGetHostId, self).tearDown()

    def test_get_a_host_id(self):
        """Test get a host id"""
        # Patch current session.user_id
        host_info = hub.get_host(self.hosts[0][0])
        self.test_session.user_id = host_info['user_id']

        host_id = self.test_session._getHostId()
        self.assertEqual(host_id, self.hosts[0][0])

    def test_get_host_id_from_nonexistent_user(self):
        """Test get a host id from a nonexistent host user"""
        # Patch current session.user_id
        host_info = hub.get_host(self.hosts[0][0])
        self.test_session.user_id = host_info['user_id'] * 10000

        host_id = self.test_session._getHostId()
        self.assertEqual(host_id, None)


class TestCheckLoginAllowed(TestCase):
    """Test Session.checkLoginAllowed"""

    def setUp(self):
        super(TestCheckLoginAllowed, self).setUp()

        self.test_user_id = self.test_session.createUser('koji_test_user')
        self.blocked_user_id = self.test_session.createUser(
            'a_blocked_user', status=koji.USER_STATUS['BLOCKED'])

    def tearDown(self):
        self.delete_user(self.test_user_id)
        self.delete_user(self.blocked_user_id)
        super(TestCheckLoginAllowed, self).tearDown()

    def test_check_against_nonexistent_user(self):
        """Test check whether to allow a nonexistent user to login"""
        self.assertRaises(koji.AuthError,
                          self.test_session.checkLoginAllowed,
                          self.test_user_id * 10000)

    def test_check_against_user(self):
        """Test check whether to allow a normal user to login"""
        self.test_session.checkLoginAllowed(self.test_user_id)

    def test_check_against_blocked_user(self):
        """Test check whether to allow a normal user to login"""
        self.assertRaises(koji.AuthError,
                          self.test_session.checkLoginAllowed,
                          self.blocked_user_id)


class TestGetUserByCredential(TestCase):
    """Test get_user_by_credential"""

    def setUp(self):
        super(TestGetUserByCredential, self).setUp()

        self.user_name = 'koji_test_user'
        self.password = 'some password'
        self.test_user_id = self.test_session.createUser(self.user_name)

        sql = 'UPDATE users SET password = %(password)s WHERE id = %(id)i'
        db.dml(sql, {'id': self.test_user_id, 'password': self.password})

    def tearDown(self):
        self.delete_user(self.test_user_id)
        super(TestGetUserByCredential, self).tearDown()

    def test_get_user(self):
        """Test get user by credential"""
        user = auth.get_user_by_credential(self.user_name, self.password)
        self.assertEqual(user['id'], self.test_user_id)
        self.assertEqual(user['name'], self.user_name)

    def test_get_nonexistent_user(self):
        """Test get user by nonexistent credential"""
        user = auth.get_user_by_credential(self.user_name, 'xxx')
        self.assertEqual(user, None)


class TestCreateSession(TestCase):
    """Test Session.createSession"""

    def setUp(self):
        super(TestCreateSession, self).setUp()

        self.user_name = 'koji_test_user'
        self.test_user_id = self.test_session.createUser(self.user_name)

    def tearDown(self):
        session_id = getattr(self, 'session_id', None)
        if session_id is not None:
            self.delete_session(session_id)

        self.delete_user(self.test_user_id)
        super(TestCreateSession, self).tearDown()

    def test_create_session(self):
        """Test create a new session for an user"""
        session = self.test_session.createSession(self.test_user_id,
                                                  '127.0.0.1',
                                                  koji.AUTHTYPE_NORMAL)
        self.assert_('session-key' in session)
        self.assert_('session-id' in session)
        self.session_id = session['session-id']


class TestMakeShared(TestCase):
    """Test Session.makeShared"""

    def setUp(self):
        super(TestMakeShared, self).setUp()

        self.user_name = 'koji_test_user'
        session = self.test_session
        self.test_user_id = session.createUser(self.user_name)
        self.session_data = session.createSession(self.test_user_id,
                                                  '127.0.0.1',
                                                  koji.AUTHTYPE_NORMAL)
        self.session_id = self.session_data['session-id']
        self.test_session.id = self.session_id

    def tearDown(self):
        self.delete_session(self.session_id)
        self.delete_user(self.test_user_id)
        super(TestMakeShared, self).tearDown()

    def test_make_shared(self):
        """Test make a session shared"""
        self.test_session.makeShared()

        sql = 'SELECT exclusive FROM sessions WHERE id = %(id)i'
        exclusive = db.singleValue(sql, {'id': self.session_id})
        self.assertEqual(exclusive, None)


class TestLogoutChild(TestCase):
    """Test Session.logoutChild"""

    def setUp(self):
        """Two new sessions are required to represent parent and child"""
        super(TestLogoutChild, self).setUp()

        self.parent_session = self.new_session()
        createUser = self.parent_session.createUser

        self.user_name = 'koji_test_user'
        self.test_user_id = createUser(self.user_name)
        self.another_user_name = 'another_koji_test_user'
        self.another_test_user_id = createUser(self.another_user_name)

        self.hostip = '127.0.0.1'
        createSession = self.parent_session.createSession
        self.parent_session_data = createSession(self.test_user_id,
                                                 self.hostip,
                                                 koji.AUTHTYPE_NORMAL)
        master = self.parent_session_data['session-id']
        self.child_session_data = createSession(self.another_test_user_id,
                                                self.hostip,
                                                koji.AUTHTYPE_NORMAL,
                                                master=master)

        # Patch the parent session to have an id
        self.parent_session.id = master

    def tearDown(self):
        self.delete_session(self.child_session_data['session-id'])
        self.delete_session(self.parent_session_data['session-id'])
        self.delete_user(self.another_test_user_id)
        self.delete_user(self.test_user_id)
        super(TestLogoutChild, self).tearDown()

    def test_logout_child_when_not_logged_in(self):
        """Test logout child session when current session does not log in"""
        self.assertRaises(koji.AuthError,
                          self.parent_session.logoutChild,
                          self.child_session_data['session-id'])

    def test_logout_child(self):
        """Test logout child session"""
        self.make_me_logged_in(self.parent_session)

        child_session_id = self.child_session_data['session-id']
        self.parent_session.logoutChild(child_session_id)

        fields = ('expired', 'exclusive')
        sql = 'SELECT %s FROM sessions WHERE id = %%(sid)i' % \
            ', '.join(fields)
        result = db.singleRow(sql, {'sid': child_session_id}, fields)

        self.assertEqual(result['expired'], True)
        self.assertEqual(result['exclusive'], None)


class TestLogout(TestCase):
    """Test Session.logout"""

    def setUp(self):
        super(TestLogout, self).setUp()

        self.user_name = 'koji_test_user'
        self.test_user_id = self.test_session.createUser(self.user_name)

        self.hostip = '127.0.0.1'
        self.session_data = self.test_session.createSession(
            self.test_user_id, self.hostip, koji.AUTHTYPE_NORMAL)
        master = self.session_data['session-id']
        db.dml('UPDATE sessions SET master = %(id)i WHERE id = %(id)i',
               {'id': master})

        # Patch the parent session to have an id
        self.test_session.id = master

    def tearDown(self):
        self.delete_session(self.session_data['session-id'])
        self.delete_user(self.test_user_id)
        super(TestLogout, self).tearDown()

    def test_logout_when_not_logged_in(self):
        """Test logout a session when not logged in yet"""
        self.assertRaises(koji.AuthError, self.test_session.logout)

    def test_logout(self):
        """Test logout a session for a logged-in user"""
        self.make_me_logged_in()
        self.test_session.logout()

        self.assertEqual(self.test_session.logged_in, False)

        fields = ('expired', 'exclusive')
        sql = 'SELECT %s FROM sessions WHERE id = %%(sid)i' % \
            ', '.join(fields)
        values = {'sid': self.session_data['session-id']}
        result = db.singleRow(sql, values, fields)
        self.assertEqual(result['expired'], True)
        self.assertEqual(result['exclusive'], None)


class TestMakeExclusive(TestCase):
    """Test Session.makeExclusive"""

    def setUp(self):
        super(TestMakeExclusive, self).setUp()

        self.user_name = 'koji_test_user'
        self.test_user_id = self.test_session.createUser(self.user_name)
        self.hostip = '127.0.0.1'

        # Create 5 sessions for test user
        self.user_session_count = 5
        session = self.test_session
        createSession = session.createSession
        self.user_session_data = [session.createSession(self.test_user_id,
                                                        self.hostip,
                                                        koji.AUTHTYPE_NORMAL)
                                  for i in xrange(self.user_session_count)]

        # Patch session's user for test
        session.user_id = self.test_user_id
        # Select one session data to associate with current session object,
        # that will be made as exclusive.
        session.id = self.user_session_data[2]['session-id']

    def tearDown(self):
        for data in self.user_session_data:
            self.delete_session(data['session-id'])
        self.delete_user(self.test_user_id)
        super(TestMakeExclusive, self).tearDown()

    def _make_first_session_exclusive(self):
        """To simulate there is already an exclusive session"""
        q = 'UPDATE sessions SET "exclusive"=TRUE WHERE id=%(sid)i'
        db.dml(q, {'sid': self.user_session_data[0]['session-id']})

    def test_subsession_cannot_become_exclusive(self):
        """Test subsession cannot become exclusive"""
        # Patch session's master for test, whatever the value assigned to
        # session.master, as long as it is not None.
        self.test_session.master = 2

        self.assertRaises(koji.GenericError, self.test_session.makeExclusive)

    def test_be_exclusive_already(self):
        """Test session is already exclusive"""
        # Patch session's exclusive for test
        self.test_session.exclusive = True

        self.assertRaises(koji.GenericError, self.test_session.makeExclusive)

    def test_make_exclusive(self):
        """Test make session exclusive"""
        self.test_session.makeExclusive()

        session_data = self.get_session(self.test_session.id)
        self.assertEqual(session_data['exclusive'], True)

    def test_when_exclusive_session_exists(self):
        """Test make session exclusive when exclusive one exists"""
        self._make_first_session_exclusive()
        self.assertRaises(koji.AuthLockError, self.test_session.makeExclusive)

    def test_force_to_make_when_exclusive_session_exists(self):
        """Test force to make session exclusive when exclusive one exists"""
        self._make_first_session_exclusive()
        self.test_session.makeExclusive(force=True)

        session_data = self.get_session(self.test_session.id)
        self.assertEqual(session_data['exclusive'], True)

        session_data = self.get_session(self.user_session_data[0]['session-id'])
        self.assertEqual(session_data['expired'], True)
        self.assertEqual(session_data['exclusive'], None)


class TestSSLLogin(TestCase):
    """Test Session.sslLogin"""

    def setUp(self):
        super(TestSSLLogin, self).setUp()

        self.nonexistent_user_name = 'X-man'
        self.user_name = 'koji_test_user'
        self.test_user_id = self.test_session.createUser(self.user_name)

        # TODO: move this into a separate method just like the
        # mock_environ_over_ssl
        self.global_context.opts = {'DNUsernameComponent': 'CN',
                                    'LoginCreatesUser': 1,
                                    }

    def tearDown(self):
        self.delete_user_sessions(self.test_user_id)
        self.delete_user(self.test_user_id)
        # Why to delete a nonexistent user, that will be created in a test
        # method
        user = hub.get_user(self.nonexistent_user_name)
        if user:
            self.delete_user_sessions(user['id'])
            self.delete_user(user['id'])
        super(TestSSLLogin, self).tearDown()

    def test_user_already_logged_in(self):
        """Test SSL login but user already logged in"""
        self.make_me_logged_in()

        self.assertRaises(koji.AuthError, self.test_session.sslLogin)

    def test_url_scheme_is_not_https(self):
        """Test SSL login but URL scheme is not HTTPS"""
        self.mock_environ_over_ssl()
        self.global_context.environ['wsgi.url_scheme'] = 'http'

        self.assertRaises(koji.AuthError, self.test_session.sslLogin)

    def test_ssl_client_verify_is_not_success(self):
        """Test SSL login but SSL_CLIENT_VERIFY is not SUCCESS"""
        self.mock_environ_over_ssl()
        self.global_context.environ['SSL_CLIENT_VERIFY'] = 'FAILURE'

        self.assertRaises(koji.AuthError, self.test_session.sslLogin)

    def test_no_client_name(self):
        """Test SSL login but there is no client name in environ"""
        self.mock_environ_over_ssl()

        self.assertRaises(koji.AuthError, self.test_session.sslLogin)

    def test_login_a_user(self):
        """Test SSL login a normal user"""
        self.mock_environ_over_ssl(self.user_name)

        session_data = self.test_session.sslLogin()
        session_data = self.get_session(session_data['session-id'])
        self.assertEqual(session_data['authtype'], koji.AUTHTYPE_SSL)
        self.assertEqual(session_data['user_id'], self.test_user_id)

    def test_login_a_nonexistent_user(self):
        """Test SSL login a nonexistent user indicated by SSL_CLIENT_S_DN_CN"""
        self.mock_environ_over_ssl(self.nonexistent_user_name)

        session_data = self.test_session.sslLogin()
        session_data = self.get_session(session_data['session-id'])
        user = hub.get_user(session_data['user_id'])
        self.assertEqual(user['name'], self.nonexistent_user_name)


class TestSessionInitialization(TestCase):
    """Test Session.__init__"""

    def setUp(self):
        super(TestSessionInitialization, self).setUp()

        self.hostip = '127.0.0.1'
        self.user_name = 'koji_test_user'
        session = self.global_context.session
        self.test_user_id = session.createUser(self.user_name)
        self.session_data = session.createSession(self.test_user_id,
                                                  self.hostip,
                                                  koji.AUTHTYPE_NORMAL)

        self.query_args = {
            'session-id': self.session_data['session-id'],
            'session-key': self.session_data['session-key'],
            'callnum': 1,
            }
        self.query_string = '&'.join(
            ('%s=%s' % (key, value)
             for key, value in self.query_args.iteritems()))

    def tearDown(self):
        self.delete_user_sessions(self.test_user_id)
        self.delete_user(self.test_user_id)
        super(TestSessionInitialization, self).tearDown()

    def test_successful_initialization(self):
        """Test a successful Session initialization"""
        self.mock_environ({'QUERY_STRING': self.query_string})

        session = auth.Session(hostip=self.hostip)
        self.assert_(session.logged_in)
