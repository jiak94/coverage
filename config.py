# If target binary takes a file as input
file_input = True

# target binary's main addr
pause_addr = ""

# target binary path
target_bin = "./readelf"

# target binary option
target_option = "-h"

# testcase folder path
testcase = "./bin"

# target shared library, can be empty
lib_list = []

# test object
# 0 = both binary and shared library
# 1 = binary ONLY
# 2 = shared library only
test_object = 1

save_result = True

# show hit count
show_hit_count = True
