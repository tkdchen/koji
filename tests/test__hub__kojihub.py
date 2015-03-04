# -*- coding: utf-8 -*-

import koji
import kojihub as hub

from base import TestCase
from koji import db


def add_a_host(host_name=None, arches=None, principal=None):
    if host_name is None:
        host_name = 'host1.example.com'
    if arches is None:
        arches = 'i386'
    if principal is None:
        principal = 'compile/%s@EXAMPLE.COM' % host_name
    return hub.RootExports().addHost(host_name, arches, principal)


def delete_host(host_id):
    """Remove a host"""
    sql = 'SELECT user_id FROM host WHERE id = %(host_id)i'
    user_id = db.singleValue(sql, {'host_id': host_id})
    sql = '''
DELETE FROM host_channels WHERE host_id = %(host_id)i;
DELETE FROM host WHERE id = %(host_id)i;
DELETE FROM sessions WHERE user_id = %(user_id)i;
DELETE FROM users WHERE id = %(user_id)i;
'''
    db.dml(sql, {'host_id': host_id, 'user_id': user_id})


def set_host_ready(hostname, ready=True):
    """Test a host active or inactive"""
    sql = 'UPDATE host SET ready = %(ready)s WHERE name = %(hostname)s'
    db.dml(sql, {'ready': ready, 'hostname': hostname})


def delete_package(pkg_info):
    if isinstance(pkg_info, basestring):
        sql = 'DELETE FROM package WHERE name = %(pkg_info)s'
    elif isinstance(pkg_info, (int, long)):
        sql = 'DELETE FROM package WHERE id = %(pkg_info)s'
    db.dml(sql, locals())


def new_task(owner_id, arch='x86_64', channel_id=None, parent=None):
    if channel_id is None:
        sql = "SELECT id FROM channels WHERE name = 'default'"
        channel_id = db.singleValue(sql, None)

    task_id = db.get_sequence_nextval('task_id_seq')
    sql = """
INSERT INTO task (id, channel_id, owner, arch, parent)
VALUES (%(task_id)i, %(channel_id)i, %(owner_id)i, %(arch)s, %(parent)s)"""
    db.dml(sql, locals())

    return task_id


def delete_task(task_id):
    sql = "DELETE FROM task WHERE id = %(task_id)i"
    db.dml(sql, locals())


def set_task_state(task_id, state, result=None):
    if result is None:
        result = ''
    sql = '''
UPDATE task SET result = %(result)s, state = %(state)s, completion_time = NOW()
WHERE id = %(task_id)d'''
    db.dml(sql, locals())


class TestTagInheritance(TestCase):
    """Test tag inheritance"""

    def setUp(self):
        super(TestTagInheritance, self).setUp()

        self.tags = (
            'dist-6E-epel',
            'dist-6E-epel-base',
            'dist-6E-epel-build',
            'dist-6E-epel-override',
            'dist-6E-epel-testing',
            'dist-6E-epel-testing-candidate',
            'dist-f10',
            'dist-f10-build',
            'dist-f10-kernel',
            'dist-f10-override',
            'dist-f10-updates',
            'dist-f10-updates-candidate',
            'dist-f10-updates-testing',
            )
        sql = 'INSERT INTO tag (name) VALUES (%(name)s)'
        for tag in self.tags:
            db.dml(sql, {'name': tag})

        # Build tag inheritances
        # Pairs of (parent_id, tag_id)
        self.tag_inheritance_rel = (
            (self.tag_id_from_name('dist-6E-epel'),
             self.tag_id_from_name('dist-6E-epel-base')),
            (self.tag_id_from_name('dist-6E-epel'),
             self.tag_id_from_name('dist-6E-epel-build')),
            (self.tag_id_from_name('dist-f10'),
             self.tag_id_from_name('dist-f10-kernel')),
            (self.tag_id_from_name('dist-f10'),
             self.tag_id_from_name('dist-f10-updates')),
            )
        sql = '''
INSERT INTO tag_inheritance (tag_id, parent_id, priority, creator_id)
VALUES (%(tag_id)i, %(parent_id)i, 1, %(creator_id)i)'''
        self.sql_values = {'tag_id': None,
                           'parent_id': None,
                           'creator_id': self.user_id,
                           }
        for parent_id, tag_id in self.tag_inheritance_rel:
            self.sql_values['tag_id'] = tag_id
            self.sql_values['parent_id'] = parent_id
            db.dml(sql, self.sql_values)

    def tearDown(self):
        # Collect event_ids before tag inheritance get deleted.
        event_ids = []
        sql = 'SELECT create_event FROM tag_inheritance ' \
                'WHERE tag_id = %(tag_id)i AND ' \
                '      parent_id = %(parent_id)i AND active = true'
        for parent_id, tag_id in self.tag_inheritance_rel:
            self.sql_values['tag_id'] = tag_id
            self.sql_values['parent_id'] = parent_id
            event_id = db.singleValue(sql, self.sql_values)
            event_ids.append(event_id)

        sql = '''
DELETE FROM tag_inheritance
WHERE tag_id = %(tag_id)i and parent_id = %(parent_id)i and active = true'''
        for parent_id, tag_id in self.tag_inheritance_rel:
            self.sql_values['tag_id'] = tag_id
            self.sql_values['parent_id'] = parent_id
            db.dml(sql, self.sql_values)

        sql = 'DELETE FROM events WHERE id IN %(event_ids)s'
        db.dml(sql, {'event_ids': event_ids})

        sql = 'DELETE FROM tag WHERE name IN %(names)s'
        db.dml(sql, {'names': self.tags})

        super(TestTagInheritance, self).tearDown()

    def tag_id_from_name(self, name):
        return db.singleValue(
            'SELECT id FROM tag WHERE name = %(name)s', locals())

    def test_read_global_inheritances(self):
        """Test read global inheritances"""
        result = hub.readGlobalInheritance()
        self.assertEqual(len(result), len(self.tag_inheritance_rel))
        for row in result:
            inheritance_rel = (row['parent_id'], row['tag_id'])
            self.assert_(inheritance_rel in self.tag_inheritance_rel)

    def test_read_inheritance_data(self):
        """Test read inheritance data"""
        tag_id = self.tag_id_from_name('dist-6E-epel-build')
        result = hub.readInheritanceData(tag_id)
        parents_count = 1
        self.assertEqual(len(result), parents_count)

        for row in result:
            self.assert_('child_id' in row)
            self.assertEqual(row['child_id'], tag_id)
            inheritance_rel = (row['parent_id'], row['child_id'])
            self.assert_(inheritance_rel in self.tag_inheritance_rel)

    def test_read_descendant_data(self):
        """Test read descendants data"""
        parent_id = self.tag_id_from_name('dist-f10')
        result = hub.readDescendantsData(parent_id)
        children_count = 2
        self.assertEqual(len(result), children_count)

        for row in result:
            inheritance_rel = (row['parent_id'], row['tag_id'])
            self.assert_(inheritance_rel in self.tag_inheritance_rel)


class TestGetReadyHosts(TestCase):
    """Test kojihub.get_ready_hosts"""

    def setUp(self):
        super(TestGetReadyHosts, self).setUp()

        self.make_me_as_admin()
        self.root_exports = hub.RootExports()

        self.host_id = add_a_host()
        self.global_context.cnx.commit()

        self.host = hub.get_host(self.host_id)
        self.session_data = self.test_session.createSession(
            self.host['user_id'], '127.0.0.1', koji.AUTHTYPE_KERB)

    def tearDown(self):
        delete_host(self.host_id)
        super(TestGetReadyHosts, self).tearDown()

    def test_no_ready_hosts_there(self):
        """Test get ready hosts but there is no ready hosts"""
        host = hub.get_ready_hosts()
        self.assertEqual(host, [])

    def test_get_ready_hosts(self):
        """Test get ready hosts"""
        hub.set_host_enabled(self.host['name'])
        set_host_ready(self.host['name'])
        sql = '''
UPDATE sessions SET update_time = NOW() - '3 minutes'::interval
WHERE id = %(sid)i'''
        db.dml(sql, {'sid': self.session_data['session-id']})

        hosts = hub.get_ready_hosts()

        self.assert_(len(hosts) > 0)

        host = hosts[0]
        channels = host.get('channels', None)
        self.assert_(isinstance(channels, list))
        self.assert_(len(channels) > 0)


class TestGetBuild(TestCase):
    """Test kojihub.get_build"""

    def test_get_build(self):
        """Test get build but no build there"""
        build = hub.get_build(1)
        self.assertEqual(build, None)


class TestNewPackage(TestCase):
    """Test kojihub.new_package"""

    def setUp(self):
        super(TestNewPackage, self).setUp()
        self.root_exports = hub.RootExports()

    def tearDown(self):
        pkg_id = getattr(self, 'pkg_id', None)
        if pkg_id is not None:
            delete_package(pkg_id)
        super(TestNewPackage, self).tearDown()

    def test_new_package(self):
        """Test create a new package that does not exist yet"""
        package_name = 'CUnit'
        self.pkg_id = hub.new_package(package_name)
        self.assert_(self.pkg_id > 0)
        self.global_context.cnx.commit()

        pkg_id = self.root_exports.getPackageID(package_name)
        self.assertEqual(pkg_id, self.pkg_id)


class TestTaskReport(TestCase):
    """Test RootExports.taskReport"""

    def setUp(self):
        super(TestTaskReport, self).setUp()

        self.root_exports = hub.RootExports()

    def test_task_report_with_no_data(self):
        """Test task report where there is no data"""
        data = self.root_exports.taskReport()
        self.assertEqual(data, [])


class HostTestCase(TestCase):
    """Base test case for Host"""

    def setUp(self):
        super(HostTestCase, self).setUp()

        self.make_me_as_admin()

        self.host_id = add_a_host()
        self.host_data = hub.get_host(self.host_id)

        # Patch Session.getHostId to get above newly created host for testing
        self.test_session.getHostId = lambda: self.host_id
        self.host = hub.Host(self.host_id)

        self.user_name = 'task_owner'
        self.task_owner_id = self.test_session.createUser(self.user_name)

        self.task_id = new_task(self.task_owner_id)
        self.subtask1_id = new_task(self.task_owner_id, parent=self.task_id)
        self.subtask2_id = new_task(self.task_owner_id, parent=self.task_id)
        self.subtask3_id = new_task(self.task_owner_id, parent=self.task_id)

    def tearDown(self):
        delete_host(self.host_id)
        delete_task(self.subtask1_id)
        delete_task(self.subtask2_id)
        delete_task(self.subtask3_id)
        delete_task(self.task_id)
        self.delete_user(self.task_owner_id)
        super(HostTestCase, self).tearDown()

    def get_task_info(self, task_id):
        return hub.Task(task_id).getInfo()

    def get_task_children(self, task_id):
        return hub.Task(task_id).getChildren()


class HostTaskUnwaitTestCase(HostTestCase):
    """Test Host.taskUnwait"""

    def test_taskUnwait(self):
        """Test clear wait data for task"""
        self.host.taskUnwait(self.task_id)
        self.global_context.cnx.commit()

        task_info = self.get_task_info(self.task_id)
        self.assertEqual(task_info['waiting'], False)

        children = self.get_task_children(self.task_id)
        for subtask in children:
            self.assertEqual(subtask['awaited'], False)


class HostTaskSetWaitTestCase(HostTestCase):
    """Test Host.taskSetWait"""

    def setUp(self):
        super(HostTaskSetWaitTestCase, self).setUp()

        self.host.taskUnwait(self.task_id)
        self.global_context.cnx.commit()

    def test_set_wait_with_all_subtasks(self):
        """Test mark task waiting and all subtasks awaited"""
        self.host.taskSetWait(self.task_id, None)
        self.global_context.cnx.commit()

        task_info = self.get_task_info(self.task_id)
        self.assertEqual(task_info['waiting'], True)

        children = self.get_task_children(self.task_id)
        for subtask in children:
            self.assertEqual(subtask['awaited'], True)

    def test_set_wait_with_partial_subtasks(self):
        """Test mark task waiting and partial subtasks awaited"""
        self.host.taskSetWait(self.task_id,
                              (self.subtask1_id, self.subtask3_id))
        self.global_context.cnx.commit()

        task_info = self.get_task_info(self.task_id)
        self.assertEqual(task_info['waiting'], True)

        task_info = self.get_task_info(self.subtask1_id)
        self.assertEqual(task_info['awaited'], True)

        task_info = self.get_task_info(self.subtask3_id)
        self.assertEqual(task_info['awaited'], True)

        task_info = self.get_task_info(self.subtask2_id)
        self.assertEqual(task_info['awaited'], False)


class HostTaskWaitCheckTestCase(HostTestCase):
    """Test Host.taskWaitCheck"""

    def test_check_task_wait_no_task(self):
        """Test return status of awaited subtask but no task with such state"""
        self.host.taskSetWait(self.task_id, None)

        finished, unfinished = self.host.taskWaitCheck(self.task_id)

        self.assertEqual(list(finished), [])
        self.assertEqual(set(unfinished),
                         set([self.subtask1_id,
                              self.subtask2_id,
                              self.subtask3_id]))

    def test_check_task_wait(self):
        """Test return status of awaited subtask"""
        self.host.taskSetWait(self.task_id, None)
        set_task_state(self.subtask1_id, koji.TASK_STATES['CLOSED'])
        set_task_state(self.subtask3_id, koji.TASK_STATES['CANCELED'])

        finished, unfinished = self.host.taskWaitCheck(self.task_id)
        self.assertEqual(set(finished),
                         set([self.subtask1_id, self.subtask3_id]))
        self.assertEqual(set(unfinished), set([self.subtask2_id]))


class HostTaskWaitTestCase(HostTestCase):
    """Test Host.taskWait"""

    def test_mark_finished_task_awaited(self):
        """Test return task results or mark tasks as awaited upon"""
        self.host.taskSetWait(self.task_id, None)
        set_task_state(self.subtask1_id, koji.TASK_STATES['CLOSED'])
        set_task_state(self.subtask3_id, koji.TASK_STATES['CANCELED'])

        finished, unfinished = self.host.taskWait(self.task_id)
        self.global_context.cnx.commit()

        self.assertEqual(set(finished),
                         set([self.subtask1_id, self.subtask3_id]))
        self.assertEqual(unfinished, [self.subtask2_id])

        for task_id in finished:
            task = hub.Task(task_id)
            self.assertEqual(task.getInfo()['awaited'], False)


class HostTaskWaitResultsTestCase(HostTestCase):
    """Test Host.taskWaitResults"""

    def setUp(self):
        super(HostTaskWaitResultsTestCase, self).setUp()
        self.task1_id = new_task(self.task_owner_id)

    def tearDown(self):
        delete_task(self.task1_id)
        super(HostTaskWaitResultsTestCase, self).tearDown()

    def test_get_empty_task_wait_results(self):
        """Test taskWaitResults where task has no subtasks"""
        results = self.host.taskWaitResults(self.task1_id, None)
        self.assertEqual(results, [])


class HostGetHostTasksTestCase(HostTestCase):
    """Test Host.getHostTasks"""

    def test_no_such_tasks_there(self):
        """Test get host tasks but no such tasks there"""
        tasks = self.host.getHostTasks()
        self.assertEqual(tasks, [])


class HostUpdateHostTestCase(HostTestCase):
    """Test Host.updateHost"""

    def test_update_host(self):
        """Test update a host's task load and ready"""
        self.host.updateHost(1.0, True)
        self.global_context.cnx.commit()

        host_data = hub.get_host(self.host.id)
        self.assertEqual(host_data['task_load'], 1.0)
        self.assertEqual(host_data['ready'], True)


class HostGetTaskTestCase(HostTestCase):
    """Test Host.getTask"""

    def test_no_such_a_task(self):
        """Test open next available task but there is no such task"""
        task = self.host.getTask()
        self.assertEqual(task, None)
