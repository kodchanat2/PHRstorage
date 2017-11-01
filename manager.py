from starbase.client.table import scanner 
import starbase
import client

HBASE_HOST = '10.0.0.1'
HBASE_PORT = 9000


def save_batch(table, rowkey, batch_data):
	c = starbase.Connection(port=HBASE_PORT)
	# print client.request_enforcement(rowkey[:rowkey.find('_')], 'save_batch', 'POST', rowkey)
	# c = starbase.Connection(host=HBASE_HOST, port=HBASE_PORT)
	table = c.table(table)

	b = table.batch()
	if b:
		b.insert(rowkey, batch_data)
		b.commit(finalize=True)

def fetch(table, rowkey, *args):
	c = starbase.Connection(port=HBASE_PORT)
	# # print client.request_enforcement('admin', 'path/path', 'GET', '1840400078741_555') IT'S work!
	print client.request_enforcement(rowkey[:rowkey.find('_')], 'fetch', 'GET', unicode(rowkey).encode())
	# c = starbase.Connection(host=HBASE_HOST, port=HBASE_PORT)
	table = c.table(table)
	if not args:
		return table.fetch(
    		rowkey,
    		)

	return table.fetch(
    		rowkey, args
    		)

def fetch_all(table):
	c = starbase.Connection(port=HBASE_PORT)
	# c = starbase.Connection(host=HBASE_HOST, port=HBASE_PORT)
	table = c.table(table)
	
	return table.fetch_all_rows(with_row_id=False, scanner_config='<Scanner maxVersions="1"></Scanner>')


def fetch_from(table, start_row, *args):
	c = starbase.Connection(port=HBASE_PORT)
	# # print client.request_enforcement(rowkey[:rowkey.find('_')], req_path_info, req_method, req_service)
	# c = starbase.Connection(host=HBASE_HOST, port=HBASE_PORT)
	print "fetch_from > start_row: " , start_row
	table = c.table(table)
	if not args:
		return table.fetch_all_rows(with_row_id=False, fail_silently=True, scanner_config='<Scanner maxVersions="1" startRow="{}"></Scanner>'.format(start_row))
	else:
		return table.fetch_all_rows(with_row_id=False, fail_silently=True, scanner_config='<Scanner maxVersions="1" startRow="{}" endRow="{}"></Scanner>'.format(start_row, args[0]))

def fetch_part(table, start_row, end_row, *args):
	c = starbase.Connection(port=HBASE_PORT)
	# # print client.request_enforcement(rowkey[:rowkey.find('_')], req_path_info, req_method, req_service)
	# c = starbase.Connection(host=HBASE_HOST, port=HBASE_PORT)
	table = c.table(table)
	if not args:
		return table.fetch_all_rows(with_row_id=True, fail_silently=True, scanner_config='<Scanner maxVersions="1" startRow="{}" endRow="{}"></Scanner>'.format(start_row, end_row))
	else:
		return table.fetch_all_rows(with_row_id=True, fail_silently=True, scanner_config='<Scanner maxVersions="1" startRow="{}" endRow="{}"><column>{}</column></Scanner>'.format(start_row, end_row, args[0]))

def insert_data(table, rowkey, columfamily, columqualifier, value):
	c = starbase.Connection(port=HBASE_PORT)
	# print client.request_enforcement(rowkey[:rowkey.find('_')], 'insert_data', 'POST', rowkey)
	# c = starbase.Connection(host=HBASE_HOST, port=HBASE_PORT)
	table = c.table(table)
	
	table.insert(
		rowkey,
		{
			columfamily: {
				columqualifier: value
			}
		}
		)

def delete_row(table, rowkey):
	c = starbase.Connection(port=HBASE_PORT)
	# print client.request_enforcement(rowkey[:rowkey.find('_')], 'delete_row', 'GET', rowkey)

	table = c.table(table)

	table.remove(rowkey)
	