import sys

def error(msg):
	print msg

	sys.exit(-1)

def check_assert(tag, result):
	try:
		assert result
	except:
		error(tag)
