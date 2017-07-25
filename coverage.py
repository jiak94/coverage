import shlex, psutil, subprocess, sys, os, time
from datetime import datetime
import json

global global_hit, so_global_hit
global_hit = list()
so_global_hit = dict()
# global start_code, end_code
# global program

def capture_bb(filename):
    with open(filename, 'r') as bb_file:
        bb_list = bb_file.readlines()

    bb_list = [x.strip() for x in bb_list]
    return bb_list

def calculate_lib_addr(maps):
    res = dict()
    for lib in lib_list:
        base_addr = maps[lib][0]
        base_addr = int(base_addr, 16)

        lib_addr_file = lib+"_addr"
        with open(lib_addr_file, 'r') as lib_bb:
            lib_map = lib_bb.readlines()
        lib_map = [x.strip() for x in lib_map]

        for idx, item in enumerate(lib_map):
            new_addr = hex(base_addr + int(item, 16))
            lib_map[idx] = new_addr

        res[lib] = lib_map
    return res

def calculate_lib_offset(maps, lib_addr):
    res = dict()
    for lib in lib_list:
        try:
            base_addr = maps[lib][0]
            base_addr = int(base_addr, 16)
            res[lib] = list()
            # for index, val in enumerate(lib_addr[lib]):
            #     res[lib][index] = hex(int(lib_addr[lib][index], 16) - base_addr)
            for addr in lib_addr[lib]:
                res[lib].append(hex(int(addr, 16) - base_addr))
        except:
            pass

    return res

def capture_log(program_exec_command, logname, testcase, lib_list, main_addr, statistic):
    command = usermode_command + " " + logname + " " + "-b " + str(main_addr) + " " + program_exec_command

    proc = subprocess.Popen(shlex.split(command), shell=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    # pause qemu

    p = psutil.Process(proc.pid)

    # import IPython; IPython.embed()
    while (p.status() is 'running'):
        time.sleep(1)

    mem_map = capture_maps(proc.pid)

    if statistic:
        mem_bb = calculate_lib_addr(mem_map)
    # try to resume process
    p.resume()

    # resume fail, kill that process, then execute again without pause
    if p.status is not 'running':
        p.kill()
        command = usermode_command + " " + logname + " " + program_exec_command
        proc = subprocess.Popen(shlex.split(command),
                                shell=False,
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        proc.wait()

    stderr = proc.stderr.read()

    # write log if any testcase crash or failed
    if len(stderr) is not 0:
        print "Error occurs while executing " + testcase
        print "Program or Qemu crashed, please check error log for more information"
        write_error_log(testcase, stderr)

    binary_bb_hit, mem_bb_hit = process_trace(logname, mem_map)
    if statistic:
        return binary_bb_hit, mem_bb_hit, mem_bb
    else:
        return binary_bb_hit, mem_bb_hit, None

def process_trace(logname, maps):
    binary_bb_hit = list()
    mem_bb_hit = dict()

    for key, val in maps.iteritems():
        mem_bb_hit[key] = list()

    with open(logname, 'r') as log:
        lines = log.readlines()
    # import IPython;IPython.embed()
    for line in lines:
        # if 'end_code' in line:
        #     end_code = line[line.find('0x'):].strip()
        #     print end_code

        # if 'start_code' in line:
        #     start_code = line[line.find('0x'):].strip()
        #     print start_code

        if 'Trace' in line:
            line = "0x" + line[line.find('[') + 1: line.rfind(']')].lstrip("0")

            if int(line, 16) >= int(start_code, 16) and int(line, 16) < int(end_code, 16):
                binary_bb_hit.append(line)
            else:
                # import IPython; IPython.embed()
                for key, val in maps.iteritems():
                    try:
                        if int(line, 16) >= int(val[0], 16) and int(line, 16) < int(val[1], 16):
                            mem_bb_hit[key].append(line)
                            break
                    except:
                        pass

    mem_bb_hit = calculate_lib_offset(maps, mem_bb_hit)

    # with open(logname+'.trace', 'a+') as f:
    #     for line in binary_bb_hit:
    #         f.write(line)
    #         f.write('\n')

    return list(set(binary_bb_hit)), mem_bb_hit

# if a "hit" addr not in bb addr lifted by ida, remove it
def correct_ida_lift(hit_list, bb_list):
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
                if addr not in so_global_hit[name]:
                    so_global_hit[name].append(addr)

        return
    for addr in hit_list:
        if addr not in global_hit:
            global_hit.append(addr)

def write_error_log(testcase, error_meg):
    error_folder = "error/"
    if not os.path.exists(error_folder):
        os.makedirs(error_folder)

    logname = datetime.now().strftime(testcase +'_error_%m-%d_%H:%M:%S')
    f = open(error_folder + logname, 'a+')
    f.write(error_meg + '\n')
    f.close()

def capture_maps(pid):
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
    # import IPython; IPython.embed()
    for lib in lib_list:
        res[lib] = list()
        # import IPython; IPython.embed()
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
        # import IPython;IPython.embed()

        # print program
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

def find_start(target_binary):
    command = 'readelf -h ' + target_binary
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = proc.stdout.read()
    stderr = proc.stdout.read()
    if len(stderr) != 0:
        return -1

    stdout = stdout.split('\n')
    for line in stdout:
        if "Entry point address" in line:
            return line[line.find('0x'):]

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

    global lib_list
    lib_list = config['library']

    file_input = config['file_input']
    global program
    program = config['target_binary']
    program_option = config['target_option']

    if len(program_option) is not 0:
        program_option = " ".join(program_option)
    else:
        program_option = ""
    testcase = config['testcase']

    if 'entry_addr' not in config or len(config['entry_addr']) == 0:
        pause_addr = find_start(program)
    else:
        pause_addr = config['entry_addr']

    save_result = config['save_result']

    with_statistic = config['show_statistic']
    # with_statistic =

    test_object = config['test_object']

    # draw_diagram = config.generate_report

    if pause_addr == -1:
        print "Please specified the entry address of the target binary"
        sys.exit(2)

    # all bb addrs lifted by ida
    if with_statistic:
        addr_filename = program + '_addr'
        bb_list = capture_bb(addr_filename)

        lib_addr_dict = dict()
        for lib in lib_list:
            with open(lib+"_addr", 'r') as f:
                addr = f.readlines()
            lib_addr_dict[lib] = addr


    for item in lib_list:
        so_global_hit[item] = list()

    # Set up a log folder for certain binary
    log_folder = program + "_trace/"

    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    print "Result"

    if with_statistic:
        print "Total Basic Blocks: " + str(len(bb_list))
        print "==========================================="

    for file in sorted(os.listdir(testcase)):
        if file_input:
            command = program + ' ' + program_option + ' ' + os.path.join(testcase, file)
        else:
            with open(os.path.join(testcase, file), 'r') as testcase_file:
                data = testcase_file.read().replace('\n', '')
            command = program + ' ' + data

        logname = log_folder +  program + '.' + file + '.log'
        binary_bb_hit, mem_bb_hit, mem_bb = capture_log(command, logname, file,lib_list, pause_addr, with_statistic)

        """
        If QEMU execute a block is not lifted by ida, adjust bb_list
        """
        if with_statistic:
            bb_list = correct_ida_lift(binary_bb_hit, bb_list)

        merge_hit(binary_bb_hit)


        print "Running " + file + ": "
        print "--Binary Hits:" + str(len(binary_bb_hit))
        if with_statistic:
            if test_object == 1 or test_object == 0:
                coverage = statistic(binary_bb_hit, bb_list)
                print "coverage: " + str(coverage) + '%'

                print "bb in binary: " + str(len(binary_bb_hit))


        if test_object is 0 or test_object is 2:
            # import IPython; IPython.embed()
            for lib in lib_list:
                merge_hit(mem_bb_hit[lib], True, lib)
                print "--"+ lib + " Hits:" + str(len(mem_bb_hit[lib]))
                if with_statistic:
                    so_coverage = statistic(mem_bb_hit[lib], mem_bb[lib])
                    print lib + " coverage: " + str(so_coverage) + '%'
            print ""

    print "==========================================="
    if with_statistic:
        overall_coverage = statistic(global_hit, bb_list)
        print "Overall coverage: " + str(overall_coverage) + '%'
        print "Adjusted Total Basic Blocks: " + str(len(bb_list))
    print "Binary Overall hit: " + str(len(global_hit))

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
    result_folder = program[program.rfind('/')+1:] + "_result/"

    if not os.path.exists(result_folder):
        os.makedirs(result_folder)

    logname = result_folder + datetime.now().strftime(program[program.rfind('/')+1:] + '_coverage_%m-%d_%H:%M:%S')
    f = open(logname, "a+")
    for addr in global_hit:
        f.write(addr)
        f.write('\n')
    f.close()
    for key, val in so_global_hit.iteritems():
        result_folder = key + "_result/"
        if not os.path.exists(result_folder):
            os.makedirs(result_folder)

        logname = result_folder + datetime.now().strftime(key + "_coverage_%m-%d_%H:%M:%S")
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
