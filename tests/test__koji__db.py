# -*- coding: utf-8 -*-

import unittest

import koji
from koji import db

from base import TestCase
from base import SessionMixin


class DataTestCase(SessionMixin, unittest.TestCase):
    """TestCase with session and data well initiated"""

    def setUp(self):
        self.session_setUp()
        self.fixture_setUp()

    def tearDown(self):
        self.fixture_tearDown()
        self.session_tearDown()

    def fixture_setUp(self):
        sql = '''
CREATE TABLE test_table (
package_name VARCHAR(100) NOT NULL,
version VARCHAR(100) NOT NULL,
release VARCHAR(100) NOT NULL)'''
        db.dml(sql, None, commit=False)
        self.sample_data = (('koji', '1.9.0', '10'),
                            ('python', '2.7.9', '8'),
                            ('perl', '5.20.2', '322'))
        values = ',\n'.join((str(data) for data in self.sample_data))
        sql = 'INSERT INTO test_table VALUES \n%s' % values
        db.dml(sql, None)

    def fixture_tearDown(self):
        db.dml('DROP TABLE IF EXISTS test_table', None)


class TestFetchMulti(DataTestCase):
    """Test fetchMulti"""

    def test_parameterized(self):
        """Test parameterized fetchMulti"""
        sql = 'SELECT * from test_table WHERE package_name = %(package_name)s'
        package_name = 'python'
        rows = db.fetchMulti(sql, locals())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 'python')

    def test_simple_query(self):
        """Test fetchMulti with simple query without parameters"""
        sql = 'SELECT * from test_table'
        rows = db.fetchMulti(sql, None)
        self.assertEqual(len(rows), len(self.sample_data))
        i = 0
        for row in rows:
            self.assertEqual(row[0], self.sample_data[i][0])
            self.assertEqual(row[1], self.sample_data[i][1])
            self.assertEqual(row[2], self.sample_data[i][2])
            i += 1

    def test_empty_result(self):
        """Test fetchMulti that returns empty result"""
        sql = 'SELECT 1 WHERE 1 = 0'
        rows = db.fetchMulti(sql, None)
        self.assertEqual(len(rows), 0)


class TestFetchSingle(DataTestCase):
    """Test fetchSingle"""

    def test_simple_query(self):
        """Test fetchSingle with simple query without parameters"""
        sql = "SELECT version FROM test_table WHERE package_name = 'koji'"
        result = db.fetchSingle(sql, None)
        self.assertEqual(result, ['1.9.0'])

        sql = "SELECT version FROM test_table"
        result = db.fetchSingle(sql, None)
        self.assertEqual(result, ['1.9.0'])

    def test_simple_query_strictly(self):
        """Test fetchSingle strictly with simple query without parameters"""
        sql = "SELECT version FROM test_table WHERE package_name = 'koji'"
        version = db.fetchSingle(sql, None, strict=True)
        self.assertEqual(version, ['1.9.0'])

        sql = "SELECT version FROM test_table"
        self.assertRaises(koji.GenericError, db.fetchSingle, sql, None, True)

    def test_parameterized(self):
        """Test parameterized fetchSingle"""
        sql = '''
SELECT version FROM test_table
WHERE package_name = %(package_name)s'''
        package_name = 'koji'
        version = db.fetchSingle(sql, locals())
        self.assertEqual(version, ['1.9.0'])

    def test_empty_result(self):
        """Test fetchSingle that returns empty result"""
        sql = 'SELECT 1 WHERE 1 = 0'
        result = db.fetchSingle(sql, None)
        self.assertEqual(result, None)

    def test_empty_result_strictly(self):
        """Test fetchSingle strictly that returns empty result"""
        sql = 'SELECT 1 WHERE 1 = 0'
        self.assertRaises(koji.GenericError, db.fetchSingle, sql, None, True)


class TestMultiRow(DataTestCase):
    """Test multiRow"""

    def test_query(self):
        """Test multiRow with specified fields"""
        sql = 'SELECT package_name, release, version FROM test_table'
        fields = ['package_name', 'release', 'version']
        result = db.multiRow(sql, None, fields)
        for row in result:
            data = (row['package_name'], row['version'], row['release'])
            self.assert_(data in self.sample_data)


class TestSingleRow(DataTestCase):
    """Test singleRow"""

    def test_query(self):
        """Test singleRow with specified fields"""
        sql = "SELECT * from test_table WHERE package_name = 'koji'"
        fields = ['package_name', 'version', 'release']
        result = db.singleRow(sql, None, fields)
        data = (result['package_name'], result['version'], result['release'])
        self.assert_(data in self.sample_data)

    def test_empty_result(self):
        """Test singleRow that returns empty result"""
        sql = 'SELECT 1 WHERE 1 = 0'
        fields = ['number_field']
        result = db.singleRow(sql, None, fields)
        self.assertEqual(result, None)


class TestSingleValue(DataTestCase):
    """Test singleValue"""

    def test_query(self):
        """Test singleValue strictly"""
        sql = 'SELECT package_name FROM test_table'
        self.assertRaises(koji.GenericError, db.singleValue, sql, None)

        sql = "SELECT package_name FROM test_table WHERE package_name = 'koji'"
        result = db.singleValue(sql, None)
        self.assertEqual(result, 'koji')

    def test_empty_result_strictly(self):
        """Test singleValue strictly that returns empty result"""
        sql = 'SELECT 1 WHERE 1 = 0'
        self.assertRaises(koji.GenericError, db.singleValue, sql, None)

    def test_empty_result(self):
        """Test singleValue that returns empty result"""
        sql = 'SELECT 1 WHERE 1 = 0'
        result = db.singleValue(sql, None, strict=False)
        self.assertEqual(result, None)


class TestDml(DataTestCase):
    """Test dml"""

    def setUp(self):
        self.new_data = {'package_name': 'vim',
                         'version': '7.4.629',
                         'release': '2',
                         }
        super(TestDml, self).setUp()

    def execute_dml(self, commit=True):
        sql = 'INSERT INTO test_table ' \
              'VALUES (%(package_name)s, %(version)s, %(release)s)'
        db.dml(sql, self.new_data, commit=commit)

    def test_commit_immediately(self):
        """Test dml that commits transaction immediately"""
        self.execute_dml()

        # Call rollback aims to test the fact that transaction has been
        # committed already.
        # You may ignore such message
        #   WARNING:  there is no transaction in progress
        # This is reported by PostgreSQL, configuration could be done to
        # disable it.
        self.global_context.cnx.rollback()

        exists = getattr(self.global_context, 'commit_pending', None)
        self.assert_(exists in (False, None))

        fields = self.new_data.keys()
        sql = "SELECT %s FROM test_table WHERE package_name = 'vim'" % (
            ', '.join(fields))
        result = db.singleRow(sql, None, fields)
        self.assertNotEqual(result, None)
        self.assertEqual(result['package_name'], self.new_data['package_name'])
        self.assertEqual(result['version'], self.new_data['version'])
        self.assertEqual(result['release'], self.new_data['release'])

    def test_commit_later(self):
        """Test dml that will commit transaction later"""
        try:
            self.execute_dml(commit=False)
            exists = getattr(self.global_context, 'commit_pending', None)
            self.assertEqual(exists, True)
        finally:
            # Ensure the pending transaction gets terminated
            self.global_context.cnx.rollback()


class TestCommitOnSuccess(DataTestCase):
    """Test decorator commit_on_success"""

    test_data = (('vim-jedi', '0.7.0', '6'),
                 ('qt5-qttools', '5.4.1', '1'),
                 ('dhcp', '4.3.2', '0.6b1'))

    def tearDown(self):
        sql = "DELETE FROM test_table WHERE package_name IN %(package_names)s"
        values = {'package_names': [item[0] for item in self.test_data]}
        db.dml(sql, values)

        super(TestCommitOnSuccess, self).tearDown()

    def make_some_changes(self):
        values = ',\n'.join((str(item) for item in self.test_data))
        sql = 'INSERT INTO test_table VALUES %s' % values
        db.dml(sql, None, commit=False)

    def make_some_changes_with_error(self):
        self.make_some_changes()
        raise ValueError

    def find_data(self, name):
        sql = "SELECT * FROM test_table WHERE package_name = %(name)s"
        return db.fetchSingle(sql, {'name': name})

    def test_commit_on_success(self):
        """Test commit when routine succeeds"""
        method = db.commit_on_success(self.make_some_changes)
        method()

        # Rollback deliberately so that I'm able to test whether the
        # transaction has been committed.
        self.global_context.cnx.rollback()

        result = self.find_data(self.test_data[0][0])
        self.assertNotEqual(result, None)

    def test_rollback_on_failure(self):
        """Test rollback when routine fails"""
        method = db.commit_on_success(self.make_some_changes_with_error)
        try:
            method()
        except ValueError:
            pass

        result = self.find_data(self.test_data[0][0])
        self.assertEqual(result, None)


class TestSequenceValue(TestCase):
    """Test sequence value"""

    def setUp(self):
        super(TestSequenceValue, self).setUp()
        db.dml('CREATE TABLE test_table (id SERIAL NOT NULL PRIMARY KEY)', None)
        self.sequence_name = 'test_table_id_seq'

    def tearDown(self):
        db.dml('DROP TABLE IF EXISTS test_table', None)
        super(TestSequenceValue, self).tearDown()

    def test_get_nextval(self):
        """Test get nextval from a specific sequence"""
        nextval = db.get_sequence_nextval(self.sequence_name)
        self.assert_(isinstance(nextval, (int, long)))
        self.assert_(nextval, 0)

