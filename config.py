# If target binary takes a file as input
file_input = False

# target binary's main addr
pause_addr = "0x400736"

# target binary path
target_bin = "./stop_test"

# testcase folder path
testcase = "./testcases"

# target shared library, can be empty
lib_list = ['libfoo.so', 'libcool.so']

# test object
# 0 = both binary and shared library
# 1 = binary ONLY
# 2 = shared library only
test_object = 2

# show hit count
show_hit_count = True
