# Intruduction
This tool is used to check the coverage of a binary or its shared objects with certain testcases

# Config
The config file needs the following variables `file_intput`, `pause_addr`, `target_bin`, `target_option`, `testcase`, `lib_list`, `test_object`, `save_result`, `show_hit_count` and `generage_report`.
* `file_input`: the target binary takes file as input, should be `True` or `False`. 
* `target_bin`: the path of the target binary. 
* `target_option`: the running option of the target binary. This value can be empty. 
* `testcase`: the path of the testcase **FOLDER**. 
* `lib_list`: specify the target shared object. This value can be a empty `list()` 
* `test_object`: specify the test object. 
    * `0`: both binary and shared object 
    * `1`: binary **ONLY** 
    * `2`: shared object **ONLY**. 
* `save_result`: Write result to file, should be `True` or `False` 
* `statistic`: If need coverage percentage, should be `True` or `False` 

# Download the modified qemu by executing

    ./qemu.sh

# Executing
If `statistic` is set to **True** in the config file, please use the ida script `bb_lift.py` to generate the static 
analysis file for both binary and its shared objects.  
Simply exectue `python coverage.py config`  
If `save_result` is set to **True**, a overall hit address will be stored in result folder.
