import psycopg2
import sys


class Database:
    conn = None
    cur = None

    def __init__(self, dbname, user, passwd, host, schema=None):
        try:
            self.conn = psycopg2.connect(host=host,
                                         database=dbname,
                                         user=user,
                                         password=passwd)
        except BaseException:
            print "Unable to Connect to Database"
            sys.exit(1)

        self.cur = self.conn.cursor()
        if schema is not None:
            try:
                self.cur.execute('SET SEARCH_PATH=%s' % schema)
            except BaseException:
                print "Unable to connect to schema"
                sys.exit(1)

    def insert(self, tablename, values):
        column = ''
        value = ''
        for key, val in values.iteritems():
            column += '"' + key + '"' + ','
            value += '\'' + val + '\','
        column = column[:-1]
        value = value[:-1]

        statement = 'INSERT INTO "%s" (%s) VALUES (%s) RETURNING id' % (
                                                                        tablename,
                                                                        column,
                                                                        value)
        try:
            self.cur.execute(statement)
        except BaseException:
            print "Unable to Insert %s" % tablename
            return False, -1

        new_id = self.cur.fetchone()[0]
        self.conn.commit()
        return True, new_id

    def update(self, tablename, values, condition):
        update = ''

        for key, val in values.iteritems():
            update += '"' + key + '"=\'' + val + '\','

        update = update[:-1]
        statement = 'UPDATE "%s" SET %s WHERE %s RETURNING id' % (
            tablename, update, condition)
        try:
            self.cur.execute(statement)
        except BaseException:
            print "Unable to Update %s" % tablename
            return False, -1

        update_id = self.cur.fetchone()[0]
        self.conn.commit()

        return True, update_id

    def select(self, tablename, column, condition=None, order=None, DESC=False):
        columns = ",".join('"' + item + '"' for item in column)
        statement = 'SELECT %s FROM "%s" ' % (columns, tablename)

        if condition is not None:
            statement += 'WHERE %s ' % condition

        if order is not None:
            statement += 'ORDER BY "%s" ' % order
            if DESC:
                statement += "DESC"
            else:
                statement += "ASC"

        try:
            self.cur.execute(statement)
        except BaseException:
            print "Can't retrieve data from %s" % tablename
            return False, None

        return True, self.cur.fetchall()

    def execute_select(self, sql_statement):
        for item in sql_statement:
            self.cur.execute(sql_statement)

        self.cur.fetchall()

    def execute_alter(self, sql_statement):
        for item in sql_statement:
            self.cur.execute(sql_statement)
        self.conn.commit()
