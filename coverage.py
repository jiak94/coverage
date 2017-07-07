import shlex
import psutil
import subprocess
import signal
from datetime import datetime
import sys, os
import config
import time

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

    binary_bb_hit, all_bb_hit = process_trace(logname)
    return binary_bb_hit, all_bb_hit, mem_bb

def process_trace(logname):
    binary_bb_hit = list()
    other_bb_hit = list()

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
                other_bb_hit.append(line)

    with open(logname+'.trace', 'a+') as f:
        for line in binary_bb_hit:
            f.write(line)
            f.write('\n')

    return list(set(binary_bb_hit)), list(set(other_bb_hit))

# if a "hit" addr not in bb addr lifted by ida, remove it
def correct_ida_lift(hit_list, bb_list):
    for addr in hit_list:
        if addr not in bb_list:
            # hit_list.remove(addr)
            bb_list.append(addr)

    hit_list = list(set(hit_list))

    return bb_list

def statistic(hit_list, bb_list):
    hit = list()

    for addr in hit_list:
        if addr in bb_list:
            hit.append(addr)

    # remove duplicate entries
    hit = list(set(hit))

    return (len(hit)/float(len(bb_list))) * 100, len(hit)

def merge_hit(global_hit, hit_map):
    for addr in hit_map:
        if addr not in global_hit:
            global_hit.append(addr)

    return global_hit

def write_error_log(testcase, error_meg):
    logname = datetime.now().strftime(testcase +'_error_%m-%d_%H:%M:%S')
    f = open(logname, 'a+')
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
        for line in format_stdout:
            if 'x' in line[2] and lib == line[3]:
                res[lib] = "0x"+line[0]
                break

    return res

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

    global usermode_command
    usermode_command = os.environ['QEMU'] + '/qemu-x86_64 -d exec -D '

    lib_list = config.lib_list

    file_input = config.file_input
    program = config.target_bin
    testcase = config.testcase
    pause_addr = config.pause_addr


    # basic block address capture from ida
    addr_filename = program + '_addr'

    # all bb addrs lifted by ida
    bb_list = capture_bb(addr_filename)

    # overall hit map
    global_hit = list()

    # Set up a log folder for certain binary
    log_folder = program + "_trace/"

    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    # Used to store results, key=testcase, vaule=[coverage, total_executed_block]
    result = dict()

    print "Result"
    print "Total Basic Blocks: " + str(len(bb_list))
    print "==========================================="

    for file in sorted(os.listdir(testcase)):
        if file_input:
            command = program + ' ' + os.path.join(testcase, file)
        else:
            with open(os.path.join(testcase, file), 'r') as testcase_file:
                data = testcase_file.read().replace('\n', '')
            command = program + ' ' + data

        logname = log_folder +  program + '.' + file + '.log'
        binary_bb_hit, other_bb_hit, mem_bb = capture_log(command, logname, file,lib_list, pause_addr)

        # bb_hit = filter(bb_hit, bb_list)
        """
        If QEMU execute a block is not lifted by ida, adjust bb_list
        """
        bb_list = correct_ida_lift(binary_bb_hit, bb_list)

        global_hit = merge_hit(global_hit, binary_bb_hit)
        result[file] = dict()

        print file + ": "
        if config.test_object == 1 or config.test_object == 0:
            coverage, bin_hit_count = statistic(binary_bb_hit, bb_list)
            if config.show_hit_count:
                print "binary hit count: " + str(bin_hit_count)
            result[file]['coverage'] = coverage
            print "coverage: " + str(coverage) + '%'

            result[file]['binary_bb'] = len(binary_bb_hit)
            print "bb in binary: " + str(len(binary_bb_hit))

            result[file]['non_binary_bb'] = len(other_bb_hit)
            print "bb not in binary: " + str(len(other_bb_hit))

            result[file]['total_bb'] = len(other_bb_hit) + len(binary_bb_hit)

        if config.test_object is 0 or config.test_object is 2:
            result[file]['libs'] = dict()
            # import IPython; IPython.embed()
            for lib in lib_list:
                # so_coverage, so_hit_count = statistic(other_bb_hit, mem_bb[lib])
                # print len(mem_bb[lib])
                # print len(other_bb_hit)
                so_coverage, so_hit_count = statistic(other_bb_hit, mem_bb[lib])
                if config.show_hit_count:
                    result[file]['libs'][lib] = so_coverage
                    print lib + " hit count: " + str(so_hit_count)
                print lib + " coverage: " + str(so_coverage) + '%'


        print ""

        # result[file]['coverage'], result[file]['hit_in_ida'] = statistic(binary_bb_hit, bb_list)


    # for file, res in sorted(result.iteritems()):
    #     print file + ":"
    #     print 'total executed bb: ' + str(res['total_bb'])
    #     print 'bb in binary: ' + str(res['binary_bb'])
    #     print 'bb in binary AND in bb addrs lifted by ida: ' + str(res['hit_in_ida'])
    #     print 'bb not in binary: ' + str(res['non_binary_bb'])

    #     for key, value in result[file]['libs'].iteritems():
    #         print key + " coverage: " + str(value) + '%'
    #     print 'coverage: ' + str(res['coverage']) + '%'
    #     print '\n'
    print "==========================================="
    overall_coverage, overall_hit = statistic(global_hit, bb_list)
    print "Adjusted Total Basic Blocks: " + str(len(bb_list))
    # print "total bb hit in binary AND bb addres lifted by ida: " + str(overall_hit)
    print "Overall coverage: " + str(overall_coverage) + '%'

if __name__ == '__main__':
    main()
