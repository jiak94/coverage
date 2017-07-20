# Intruduction
This tool is used to check the coverage of a binary or its shared objects with certain testcases

# Config
The config file needs the following variables `file_intput`, `pause_addr`, `target_bin`, `target_option`, `testcase`, `lib_list`, `test_object`, `save_result`, `show_hit_count` and `generage_report`.

* `file_input`: the target binary takes file as input, should be `True` or `False`.
* `pause_addr`: the address that qemu will pause the get the memory mapping. This value can be empty.
* `target_bin`: the path of the target binary.
* `target_option`: the running option of the target binary. This value can be empty.
* `testcase`: the path of the testcase **FOLDER**.
* `lib_list`: specify the target shared object. This value can be a empty `list()`
* `test_object`: specify the test object. 
    * `0`: both binary and shared object
    * `1`: binary **ONLY**
    * `2`: shared object **ONLY**.
* `save_result`: Write result to file, should be `True` or `False`
* `show_hit_count`: If need to show the hit count for binary and shared object, should be `True` or `False`
* `generage_report`: If need to generage a graph to show the change of each testcase, should be `True` or `False`

# Before Start
