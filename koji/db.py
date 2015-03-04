# python library

# db utilities for koji
# Copyright (c) 2005-2014 Red Hat, Inc.
#
#    Koji is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; 
#    version 2.1 of the License.
#
#    This software is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this software; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
# Authors:
#       Mike McLean <mikem@redhat.com>


import logging
import sys
import pgdb
import time
import traceback
_quoteparams = None
try:
    from pgdb import _quoteparams
except ImportError:
    pass
assert pgdb.threadsafety >= 1
import context

import koji

## Globals ##
_DBopts = None
# A persistent connection to the database.
# A new connection will be created whenever
# Apache forks a new worker, and that connection
# will be used to service all requests handled
# by that worker.
# This probably doesn't need to be a ThreadLocal
# since Apache is not using threading,
# but play it safe anyway.
_DBconn = context.ThreadLocal()

logger = logging.getLogger('koji.db')


class DBWrapper:
    def __init__(self, cnx):
        self.cnx = cnx

    def __getattr__(self, key):
        if not self.cnx:
            raise StandardError, 'connection is closed'
        return getattr(self.cnx, key)

    def cursor(self, *args, **kw):
        if not self.cnx:
            raise StandardError, 'connection is closed'
        return CursorWrapper(self.cnx.cursor(*args, **kw))

    def close(self):
        # Rollback any uncommitted changes and clear the connection so
        # this DBWrapper is no longer usable after close()
        if not self.cnx:
            raise StandardError, 'connection is closed'
        self.cnx.cursor().execute('ROLLBACK')
        #We do this rather than cnx.rollback to avoid opening a new transaction
        #If our connection gets recycled cnx.rollback will be called then.
        self.cnx = None


class CursorWrapper:
    def __init__(self, cursor):
        self.cursor = cursor
        self.logger = logger

    def __getattr__(self, key):
        return getattr(self.cursor, key)

    def _timed_call(self, method, args, kwargs):
        start = time.time()
        ret = getattr(self.cursor,method)(*args,**kwargs)
        self.logger.debug("%s operation completed in %.4f seconds", method, time.time() - start)
        return ret

    def fetchone(self,*args,**kwargs):
        return self._timed_call('fetchone',args,kwargs)

    def fetchall(self,*args,**kwargs):
        return self._timed_call('fetchall',args,kwargs)

    def quote(self, operation, parameters):
        if _quoteparams is not None:
            quote = _quoteparams
        elif hasattr(self.cursor, "_quoteparams"):
            quote = self.cursor._quoteparams
        else:
            quote = lambda a,b: a % b
        try:
            return quote(operation, parameters)
        except Exception:
            self.logger.exception('Unable to quote query:\n%s\nParameters: %s', operation, parameters)
            return "INVALID QUERY"

    def execute(self, operation, parameters=()):
        debug = self.logger.isEnabledFor(logging.DEBUG)
        if debug:
            self.logger.debug(self.quote(operation, parameters))
            start = time.time()
        try:
            ret = self.cursor.execute(operation, parameters)
        except Exception:
            self.logger.error('Query failed. Query was: %s', self.quote(operation, parameters))
            raise
        if debug:
            self.logger.debug("Execute operation completed in %.4f seconds", time.time() - start)
        return ret


## Functions ##
def provideDBopts(**opts):
    global _DBopts
    if _DBopts is None:
        _DBopts = opts

def setDBopts(**opts):
    global _DBopts
    _DBopts = opts

def getDBopts():
    return _DBopts

def connect():
    global _DBconn
    if hasattr(_DBconn, 'conn'):
        # Make sure the previous transaction has been
        # closed.  This is safe to call multiple times.
        conn = _DBconn.conn
        try:
            # Under normal circumstances, the last use of this connection
            # will have issued a raw ROLLBACK to close the transaction. To
            # avoid 'no transaction in progress' warnings (depending on postgres
            # configuration) we open a new one here.
            # Should there somehow be a transaction in progress, a second
            # BEGIN will be a harmless no-op, though there may be a warning.
            conn.cursor().execute('BEGIN')
            conn.rollback()
            return DBWrapper(conn)
        except pgdb.Error:
            del _DBconn.conn
    #create a fresh connection
    opts = _DBopts
    if opts is None:
        opts = {}
    try:
        conn = pgdb.connect(**opts)
    except Exception:
        logger.error(''.join(traceback.format_exception(*sys.exc_info())))
        raise
    # XXX test
    # return conn
    _DBconn.conn = conn

    return DBWrapper(conn)


def commit_on_success(func):
    """Ensure transaction is committed after function succeeds to run"""
    def _func(*args, **kwargs):
        cnx = context.context.cnx
        try:
            result = func(*args, **kwargs)
        except:
            cnx.rollback()
            raise
        else:
            cnx.commit()
        return result
    return _func


### Database query interfaces ###


def fetchMulti(query, values):
    """Run the query and return all rows"""
    cnx = context.context.cnx
    c = cnx.cursor()
    try:
        if values is None:
            c.execute(query)
        else:
            c.execute(query, values)
        return c.fetchall()
    finally:
        c.close()


def fetchSingle(query, values, strict=False):
    """Run the query and return a single row

    If strict is true, raise an error if the query returns more or less than
    one row.
    """
    results = fetchMulti(query, values)
    numRows = len(results)
    if numRows == 0:
        if strict:
            raise koji.GenericError, 'query returned no rows'
        else:
            return None
    elif strict and numRows > 1:
        raise koji.GenericError, \
            'multiple rows returned for a single row query'
    else:
        return results[0]


def multiRow(query, values, fields):
    """Return all rows from "query".  Named query parameters
    can be specified using the "values" map.  Results will be returned
    as a list of maps.  Each map in the list will have a key for each
    element in the "fields" list.  If there are no results, an empty
    list will be returned."""
    return [dict(zip(fields, row)) for row in fetchMulti(query, values)]


def singleRow(query, values, fields, strict=False):
    """Return a single row from "query".  Named parameters can be
    specified using the "values" map.  The result will be returned as
    as map.  The map will have a key for each element in the "fields"
    list.  If more than one row is returned and "strict" is true, a
    GenericError will be raised.  If no rows are returned, and "strict"
    is True, a GenericError will be raised.  Otherwise None will be
    returned."""
    row = fetchSingle(query, values, strict)
    if row:
        return dict(zip(fields, row))
    else:
        #strict enforced by fetchSingle
        return None


def singleValue(query, values=None, strict=True):
    """Perform a query that returns a single value.

    Note that unless strict is True a return value of None could mean either
    a single NULL value or zero rows returned.
    """
    if values is None:
        values = {}
    row = fetchSingle(query, values, strict)
    if row:
        return row[0]
    else:
        # don't need to check strict here, since that was already handled by singleRow()
        return None


def dml(operation, values, commit=True):
    """Run an insert, update, or delete. Return number of rows affected"""
    ctx = context.context
    c = ctx.cnx.cursor()
    try:
        c.execute(operation, values)
        ret = c.rowcount
        logger.debug("Operation affected %s row(s)", ret)
    finally:
        c.close()
    if commit:
        ctx.cnx.commit()
        ctx.commit_pending = False
    else:
        ctx.commit_pending = True
    return ret


### Some high level APIs ###


def get_sequence_nextval(sequence, strict=True):
    query = 'SELECT nextval(%(sequence)s)'
    return singleValue(query, {'sequence': sequence}, strict=True)


if __name__ == "__main__":
    setDBopts( database = "test", user = "test")
    print "This is a Python library"
