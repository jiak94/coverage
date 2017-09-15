# Intruduction
This tool is used to check the coverage of a binary or its shared objects with certain testcases. It's based on a modified
qemu.

# Config File
The config file needs the following variables 
`file_intput`, 
`target_bin`, 
`target_option`, 
`lib_list`, 
`test_object`,
and `statistic`

* `file_input`: the target binary takes file as input, should be `True` or `False`. 
* `target_bin`: the path of the target binary. 
* `target_option`: the running option of the target binary. This value can be empty. 
* `lib_list`: specify the target shared object. This value can be a empty `list()` 
* `test_object`: specify the test object. 
    * `0`: both binary and shared object 
    * `1`: binary **ONLY** 
    * `2`: shared object **ONLY**. 
* `statistic`: If need coverage percentage, should be `True` or `False` 

# Download the modified qemu by executing

    ./qemu.sh

# Basic Usage

    import coverage
    conf = open('./readelf.json')
    tool = coverage.Coverage(conf)

    result = tool.check_coverage('./testcases/readelf')

    tool.pretty_print(result)

# Method and Variables

* `check_coverage(testcase)`
    * check the code coverage feeding in the testcase
    * testcase: the path of the testcase file
    * return: dictionary.
    
    {
        testcase: "testcase path",
        hash: "testcase hash"
        binary_bb_hit: list of hitted basic block address,
        bb_list: list of all basic block address (need addr files),
        libs_bb_hit: dictionary contains hitted basic block address for each target library
        libs_bb_list: dictionary contains all basic block address for each target library
    }

* `pretty_print(result)`
    * print the result in readable format
    * result: dictionary returned by `check_coverage`

* `pretty_print_overall()`
    * print the overall result

* `Coverage(config_file)`
    * initialize the coverage tool
    * `config_file`: configuration file handler
