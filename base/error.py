import sys

'''
	print error and exit
'''
def error(msg):
	print msg

	sys.exit(-1)

'''
	for assert check
'''
def check_assert(tag, result):
	try:
		assert result
	except:
		error(tag)
