import shlex, psutil, subprocess, sys, os, time
from datetime import datetime
import json

global binary_overall_hit, so_overall_hit
binary_overall_hit = list()
so_overall_hit = dict()

def capture_bb(filename):
    with open(filename, 'r') as bb_file:
        bb_list = bb_file.readlines()

    bb_list = [x.strip() for x in bb_list]
    return bb_list

def calculate_lib_addr(maps):
    pass
#     res = dict()
#     for lib in lib_list:
#         base_addr = maps[lib][0]
#         base_addr = int(base_addr, 16)

#         lib_addr_file = lib+"_addr"
#         with open(lib_addr_file, 'r') as lib_bb:
#             lib_map = lib_bb.readlines()
#         lib_map = [x.strip() for x in lib_map]

#         for idx, item in enumerate(lib_map):
#             new_addr = hex(base_addr + int(item, 16))
#             lib_map[idx] = new_addr

#         res[lib] = lib_map
#     return res

def calculate_lib_offset(maps, lib_addr):
    res = dict()
    for lib in lib_list:
        try:
            base_addr = maps[lib][0]
            base_addr = int(base_addr, 16)
            res[lib] = list()

            for addr in lib_addr[lib]:
                res[lib].append(hex(int(addr, 16) - base_addr))

            res[lib] = list(set(res[lib]))
        except:
            pass

    return res

def capture_log(program_exec_command, logname, testcase, lib_list):
    command = usermode_command + " " + logname + " " + "-b " + " ".join(program_exec_command)

    proc = subprocess.Popen(shlex.split(command),
                            shell=False,
                            stderr=subprocess.PIPE,
                            stdout=subprocess.PIPE)

    p = psutil.Process(proc.pid)

    while (p.status() is 'running'):
        time.sleep(1)

    mem_map = get_mem_mapping(proc.pid)

    # if statistic:
        # calculate the REAL addr for target library
        # libs_loaded_addr = calculate_lib_addr(mem_map)

    # try to resume process
    p.resume()

    # resume fail, kill that process, then execute again without pause
    if p.status is not 'running':
        p.kill()
        command = usermode_command + " " + logname + " " + " ".join(program_exec_command)
        proc = subprocess.Popen(shlex.split(command),
                                shell=False,
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        proc.wait()

    stderr = proc.stderr.read()

    # write log if any std err return
    if len(stderr) is not 0:
        print "Error occurs while executing " + str(testcase)
        print "Program or Qemu crashed, please check error log for more information"
        write_error_log(testcase, stderr)

    binary_bb_hit, libs_bb_hit = process_trace(logname, mem_map)

    return binary_bb_hit, libs_bb_hit

def process_trace(logname, maps):
    binary_bb_hit = list()
    libs_bb_hit = dict()

    for key, val in maps.iteritems():
        libs_bb_hit[key] = list()

    with open(logname, 'r') as log:
        lines = log.readlines()

    for line in lines:
        if 'Trace' in line:
            line = "0x" + line[line.find('[') + 1: line.rfind(']')].lstrip("0")

            if int(line, 16) >= int(start_code, 16) and int(line, 16) < int(end_code, 16):
                binary_bb_hit.append(line)
            else:
                for key, val in maps.iteritems():
                    try:
                        if int(line, 16) >= int(val[0], 16) and int(line, 16) < int(val[1], 16):
                            libs_bb_hit[key].append(line)
                            break
                    except:
                        pass

    libs_bb_hit = calculate_lib_offset(maps, libs_bb_hit)

    testcase_name = logname[logname.rfind('/')+1:]
    testcase_name = testcase_name[testcase_name.find('.')+1:testcase_name.rfind('.')]

    filename = datetime.now().strftime(result_folder + logname[logname.rfind('/')+1:logname.rfind('.')]+"_hit_%H:%M:%S")
    with open(filename, 'a+') as f:
        for line in binary_bb_hit:
            f.write(line)
            f.write('\n')

    for key, val in libs_bb_hit.iteritems():
        filename = datetime.now().strftime(result_folder + key +'_'+testcase_name+'_%m-%d_%H:%M:%S')
        with open(filename, 'a+') as f:
            for line in val:
                f.write(line)
                f.write('\n')

    return list(set(binary_bb_hit)), libs_bb_hit

# if a "hit" addr not in bb addr lifted by ida, remove it
def correct_static_analysis(hit_list, bb_list):
    for addr in hit_list:
        if addr not in bb_list:
            # hit_list.remove(addr)
            bb_list.append(addr)

    hit_list = list(set(hit_list))

    return bb_list

def statistic(hit_list, bb_list):
    return (len(hit_list)/float(len(bb_list))) * 100

def merge_hit(hit_list, so=False, name=None):
    if so:
        if name is None:
            return
        else:
            for addr in hit_list:
                if addr not in so_overall_hit[name]:
                    so_overall_hit[name].append(addr)

        so_overall_hit[name] = list(set(so_overall_hit[name]))
        return
    for addr in hit_list:
        if addr not in binary_overall_hit:
            binary_overall_hit.append(addr)

def write_error_log(testcase, error_meg):
    error_folder = "error/"
    if not os.path.exists(error_folder):
        os.makedirs(error_folder)

    logname = datetime.now().strftime(testcase +'_error_%m-%d_%H:%M:%S')
    f = open(error_folder + logname, 'a+')
    f.write(error_meg + '\n')
    f.close()

def get_mem_mapping(pid):
    res = dict()
    command = "pmap " + str(pid)

    proc = subprocess.Popen(shlex.split(command), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = proc.stdout.read()

    stdout = stdout.split('\n')

    format_stdout = list()
    for line in stdout:
        split_line = line.split(' ')
        split_line = filter(None, split_line)
        split_line = [x for x in split_line if '[' not in x]
        split_line = [x for x in split_line if ']' not in x]
        format_stdout.append(split_line)

    format_stdout = filter(None, format_stdout)
    for lib in lib_list:
        res[lib] = list()
        for line in format_stdout:
            try:
                if 'x' in line[2] and lib == line[3]:
                    start = "0x"+line[0]
                    size = line[1][:-1]

                    res[lib].append(start)
                    res[lib].append(calculate(start, int(size)))
                    break
            except:
                pass

    for line in format_stdout:
        if 'x' in line[2] and line[3] in program:
            global start_code
            global end_code
            start_code = "0x"+line[0]
            size = line[1][:-1]
            end_code = calculate(start_code, int(size))
            break

    return res

def calculate(start, size):
    return hex(int(start, 16) + 1024 * size)

def write_hit_log(hit_list):
    f = open('hit_addr.log', 'a+')

    for addr in hit_list:
        f.write(addr)
        f.write('\n')

    f.close()

def main():
    if 'QEMU' not in os.environ:
        print "Please set QEMU binary root. export QEMU=qemu_bin"
        sys.exit(2)
    if len(sys.argv) < 2:
        print "Usage: python coverage.py config.json"
        sys.exit(2)

    with open(sys.argv[1]) as config_file:
        config = json_load(config_file)

    global usermode_command
    usermode_command = os.environ['QEMU'] + '/qemu-x86_64 -d exec -D '


    # Load configuration
    global lib_list, program

    lib_list = config['library']
    file_input = config['file_input']
    program = config['target_binary']
    program_option = " ".join(config['target_option'])
    testcase = config['testcase']
    save_result = config['save_result']
    with_statistic = config['show_statistic']
    test_object = config['test_object']
    # draw_diagram = config.generate_report

    global result_folder

    # Set up a log/result folder for certain binary
    result_folder = program[program.rfind('/')+1:] + "_result/"
    log_folder = program + "_trace/"

    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    if not os.path.exists(result_folder):
        os.makedirs(result_folder)


    # read in static analysis result
    if with_statistic:
        addr_filename = program + '_addr'
        bb_list = capture_bb(addr_filename)

        lib_addr_dict = dict()
        for lib in lib_list:
            with open(lib+"_addr", 'r') as f:
                addr = f.readlines()
            lib_addr_dict[lib] = addr

    # Initialize the so_overall_hit dictionary
    for item in lib_list:
        so_overall_hit[item] = list()

    # Print out execution result
    print "Result"

    # Print out static analysis result
    if with_statistic:
        print "Total Basic Blocks: " + str(len(bb_list))
        print "==========================================="

    for file in sorted(os.listdir(testcase)):
        command = list()
        command.append(program)
        if file_input:
            command.append(program_option)
            command.append(os.path.join(testcase, file))

        else:
            with open(os.path.join(testcase, file), 'r') as testcase_file:
                data = testcase_file.read().replace('\n', '')
            command.append(data)

        logname = log_folder +  program + '.' + file + '.log'

        binary_bb_hit, libs_bb_hit = capture_log(command, logname, file,lib_list)

        """
        If QEMU execute a block is not lifted by ida, adjust bb_list
        """

        if with_statistic:
            bb_list = correct_static_analysis(binary_bb_hit, bb_list)
            for key, val in libs_bb_hit.iteritems():
                libs_bb_hit[key] = correct_static_analysis(val, lib_addr_dict[key])

        # Update binary_overall_hit
        merge_hit(binary_bb_hit)

        print "Running " + file + ": "
        print "--Binary Hits:" + str(len(binary_bb_hit))

        if with_statistic:
            if test_object == 1 or test_object == 0:
                coverage = statistic(binary_bb_hit, bb_list)
                print "coverage: " + str(coverage) + '%'
                print "bb hit in binary: " + str(len(binary_bb_hit))

        if test_object is 0 or test_object is 2:
            for lib in lib_list:
                merge_hit(libs_bb_hit[lib], True, lib)
                print "--"+ lib + " Hits:" + str(len(libs_bb_hit[lib]))

                if with_statistic:
                    so_coverage = statistic(libs_bb_hit[lib], lib_addr_dict[lib])
                    print lib + " coverage: " + str(so_coverage) + '%'
            print ""

    print "==========================================="

    if with_statistic:
        overall_coverage = statistic(binary_overall_hit, bb_list)
        print "Overall coverage: " + str(overall_coverage) + '%'
        print "Adjusted Total Basic Blocks: " + str(len(bb_list))
    print "Binary Overall hit: " + str(len(binary_overall_hit))

    if save_result:
        write_result(program)

    # if draw_diagram:
    #     result_folder = program[program.rfind('/')+1:] + "_result/"
    #     if not os.path.exists(result_folder):
    #         print "Result Folder does not exists"
    #         sys.exit(2)

    #     # result_files = [x for f in listdir(result_folder) if isfile(join(result_folder, f))]
    #     result_files = list()
    #     for subdir, dirs, files, in os.walk(result_folder):
    #         for file in files:
    #             result_files.append(join(subdir, file))

    #     classified_result = pg.classify_result(result_files)

    #     coverage_dict = dict()

    #     for key, val in classified_result.iteritems():
    #         if key == program[program.rfind('/')+1:]:
    #             coverage = pg.parse_results(val, bb_list)
    #             coverage_dict[key] = coverage
    #         else:
    #             coverage = pg.parse_results(val, lib_addr_dict[key])
    #             coverage_dict[key] = coverage

    #     for key, val in coverage_dict.iteritems():
    #         pg.generate_report(val, key)

def write_result(program):
    logname = result_folder + datetime.now().strftime(program[program.rfind('/')+1:] + '_overall_%m-%d_%H:%M:%S')
    f = open(logname, "a+")
    for addr in binary_overall_hit:
        f.write(addr)
        f.write('\n')
    f.close()
    for key, val in so_overall_hit.iteritems():
        logname = result_folder + datetime.now().strftime(key + "_overall_%m-%d_%H:%M:%S")
        f = open(logname, "a+")
        for addr in val:
            f.write(addr)
            f.write('\n')
        f.close()

def json_load(file_handle):
    return _byteify(
        json.load(file_handle, object_hook=_byteify),
        ignore_dicts=True
    )

def _byteify(data, ignore_dicts = False):
    if isinstance(data, unicode):
        return data.encode('utf-8')
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    return data

if __name__ == '__main__':
    main()
