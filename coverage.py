import shlex, psutil, subprocess, signal, sys, os, time
from os.path import join
from datetime import datetime
import config
import check_progress as pg

global global_hit, so_global_hit
global_hit = list()
so_global_hit = dict()

def capture_bb(filename):
    with open(filename, 'r') as bb_file:
        bb_list = bb_file.readlines()

    bb_list = [x.strip() for x in bb_list]
    return bb_list

def calculate_lib_addr(maps):
    res = dict()
    for lib in config.lib_list:
        base_addr = maps[lib]
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
    for lib in config.lib_list:
        base_addr = maps[lib]
        base_addr = int(base_addr, 16)
        res[lib] = list()
        # for index, val in enumerate(lib_addr[lib]):
        #     res[lib][index] = hex(int(lib_addr[lib][index], 16) - base_addr)
        for addr in lib_addr[lib]:
            res[lib].append(hex(int(addr, 16) - base_addr))

    return res

def capture_log(program_exec_command, logname, testcase, lib_list, main_addr):
    command = usermode_command + " " + logname + " " + "-b " + str(main_addr) + " " + program_exec_command

    proc = subprocess.Popen(shlex.split(command), shell=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    # pause qemu

    p = psutil.Process(proc.pid)

    # import IPython; IPython.embed()
    while (p.status is 'running'):
        time.sleep(1)

    mem_map = capture_maps(proc.pid)
    mem_bb = calculate_lib_addr(mem_map)
    # try to resume process
    p.resume()

    # resume fail, kill that process, then execute again without pause
    if p.status is not 'running':
        os.kill(proc.pid, signal.SIGKILL)
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

    binary_bb_hit, mem_bb_hit = process_trace(logname, mem_bb, mem_map)
    return binary_bb_hit, mem_bb_hit, mem_bb

def process_trace(logname, mem_bb, maps):
    binary_bb_hit = list()
    mem_bb_hit = dict()

    for key, val in maps.iteritems():
        mem_bb_hit[key] = list()

    with open(logname, 'r') as log:
        lines = log.readlines()

    for line in lines:
        if 'end_code' in line:
            end_code = line[line.find('0x'):].strip()

        if 'start_code' in line:
            start_code = line[line.find('0x'):].strip()

        if 'Trace' in line:
            line = "0x" + line[line.find('[') + 1: line.rfind(']')].lstrip("0")

            if int(line, 16) >= int(start_code, 16) and int(line, 16) < int(end_code, 16):
                binary_bb_hit.append(line)
            else:
			    for key, val in mem_bb.iteritems():
			        if line in mem_bb[key]:
						mem_bb_hit[key].append(line)

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

    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

    for lib in config.lib_list:
        res[lib] = '0x000'
        for line in format_stdout:
            try:
                if 'x' in line[2] and lib == line[3]:
                    res[lib] = "0x"+line[0]
                    break
            except:
                pass

    return res

def write_hit_log(hit_list):
    f = open('hit_addr.log', 'a+')

    for addr in hit_list:
        f.write(addr)
        f.write('\n')

    f.close()

def find_shortest(testcase1, testcase2):
    pass

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

    global usermode_command
    usermode_command = os.environ['QEMU'] + '/qemu-x86_64 -d exec -D '

    lib_list = config.lib_list

    file_input = config.file_input
    program = config.target_bin
    program_option = config.target_option
    testcase = config.testcase
    pause_addr = config.pause_addr
    save_result = config.save_result

    with_statistic = config.statistic
    draw_diagram = config.draw_diagram

    if len(pause_addr) == 0:
        pause_addr = find_start(program)

    if pause_addr == -1:
        print "Please specified the start address of the target binary"
        sys.exit(2)

    lib_addr_dict = dict()

    for lib in lib_list:
        with open(lib+"_addr", 'r') as f:
            addr = f.readlines()
        lib_addr_dict[lib] = addr

    # basic block address capture from ida
    addr_filename = program + '_addr'

    # all bb addrs lifted by ida
    if with_statistic:
        bb_list = capture_bb(addr_filename)

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
        binary_bb_hit, mem_bb_hit, mem_bb = capture_log(command, logname, file,lib_list, pause_addr)

        """
        If QEMU execute a block is not lifted by ida, adjust bb_list
        """
        if with_statistic:
            bb_list = correct_ida_lift(binary_bb_hit, bb_list)

        merge_hit(binary_bb_hit)

        if with_statistic:
            print file + ": "
            if config.test_object == 1 or config.test_object == 0:
                coverage = statistic(binary_bb_hit, bb_list)
                if config.show_hit_count:
                    print "binary hit count: " + str(len(binary_bb_hit))
                print "coverage: " + str(coverage) + '%'

                print "bb in binary: " + str(len(binary_bb_hit))


            if config.test_object is 0 or config.test_object is 2:
                # import IPython; IPython.embed()
                for lib in lib_list:
                    so_coverage = statistic(mem_bb_hit[lib], mem_bb[lib])
                    merge_hit(mem_bb_hit[lib], True, lib)
                    if config.show_hit_count:
                        print lib + " hit count: " + str(len(mem_bb_hit[lib]))
                    print lib + " coverage: " + str(so_coverage) + '%'


            print ""

    print "==========================================="
    if with_statistic:
        overall_coverage = statistic(global_hit, bb_list)
        print "Overall coverage: " + str(overall_coverage) + '%'
        print "Adjusted Total Basic Blocks: " + str(len(bb_list))
    print "Overall hit: " + str(len(global_hit))

    if save_result:
        write_result(program)

    if draw_diagram:
        result_folder = program[program.rfind('/')+1:] + "_result/"
        if not os.path.exists(result_folder):
            print "Result Folder does not exists"
            sys.exit(2)

        # result_files = [x for f in listdir(result_folder) if isfile(join(result_folder, f))]
        result_files = list()
        for subdir, dirs, files, in os.walk(result_folder):
            for file in files:
                result_files.append(join(subdir, file))

        classified_result = pg.classify_result(result_files)

        coverage_dict = dict()

        for key, val in classified_result.iteritems():
            if key == program[program.rfind('/')+1:]:
                coverage = pg.parse_results(val, bb_list)
                coverage_dict[key] = coverage
            else:
                coverage = pg.parse_results(val, lib_addr_dict[key])
                coverage_dict[key] = coverage

        for key, val in coverage_dict.iteritems():
            pg.generate_report(val, key)

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
        logname = datetime.now().strftime(key + "_coverage_%m-%d_%H:%M:%S")
        f = open(logname, "a+")
        for addr in val:
            f.write(addr)
            f.write('\n')
        f.close()

if __name__ == '__main__':
    main()
