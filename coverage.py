import subprocess
from datetime import datetime
import sys, os

# python bb_stat.py program_path [testcase_folder] [@@]

# TODO
# count all executed bb
# ask what platform
# use usermode or full system mode

def capture_bb(filename):
    with open(filename, 'r') as bb_file:
        bb_map = bb_file.readlines()

    bb_map = [x.strip() for x in bb_map]
    return bb_map
def capture_log(program_exec_command, logname, testcase):
    command = usermode_command + " " + logname + " " + program_exec_command
    proc = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    stderr = proc.stderr.read()
    # print command
    if len(stderr) is not 0:
        print "Error occurs while executing " + testcase
        print "Program or Qemu crashed, please check error log for more information"
        write_error_log(testcase, stderr)

    binary_bb_hit, all_bb_hit = process_trace(logname)
    return binary_bb_hit, all_bb_hit

def process_trace(logname):
    binary_bb_hit = list()
    all_bb_hit = list()

    with open(logname, 'r') as log:
        lines = log.readlines()

    for line in lines:
        if 'end_code' in line:
            end_code = line[line.find('0x'):].strip()

        if 'start_code' in line:
            start_code = line[line.find('0x'):].strip()

        if 'Trace' in line:
            line = "0x" + line[line.find('[') + 1: line.rfind(']')].lstrip("0")
            if line not in all_bb_hit:
                all_bb_hit.append(line)

            if int(line, 16) >= int(start_code, 16) and int(line, 16) < int(end_code, 16) and line not in binary_bb_hit:
                binary_bb_hit.append(line)

    with open(logname+'.trace', 'a+') as f:
        for line in binary_bb_hit:
            f.write(line)
            f.write('\n')

    return binary_bb_hit, all_bb_hit

# if a "hit" addr not in bb addr lifted by ida, remove it
def filter(hit_list, bb_map):
    for addr in hit_list:
        if addr not in bb_map:
            hit_list.remove(addr)

    hit_list = list(set(hit_list))

    return hit_list

def statistic(hit_list, bb_map):
    # hit = len(hit_list)
    # hit_list = list(set(hit_list))
    hit = 0
    # import IPython; IPython.embed()
    for addr in hit_list:
        # if addr not in bb_map:
        #     hit -= 1
        if addr in bb_map:
            hit += 1

    # import IPython; IPython.embed()
    return (hit/float(len(bb_map))) * 100, hit


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
    usermode_command = os.environ['QEMU'] + '/qemu-x86_64 -d exec -D'


    if len(sys.argv) < 3:
        print "Usage: python bb_stat.py program_path testcase_folder [@@]"
        sys.exit(2)

    if '@@' in sys.argv :
        file_input = True
    else:
        file_input = False

    program = sys.argv[1]
    testcase = sys.argv[2]

    # basic block address capture from ida
    addr_filename = program + '_addr'

    # all bb addrs lifted by ida
    bb_map = capture_bb(addr_filename)

    # overall hit map
    global_hit = list()

    # Set up a log folder for certain binary
    log_folder = program + "_trace/"

    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    # Used to store results, key=testcase, vaule=[coverage, total_executed_block]
    result = dict()

    for file in os.listdir(testcase):
        if file_input:
            command = program + ' ' + os.path.join(testcase, file)
        else:
            with open(os.path.join(testcase, file), 'r') as testcase_file:
                data = testcase_file.read().replace('\n', '')
            command = program + ' ' + data

        logname = log_folder +  program + '.' + file + '.log'
        binary_bb_hit, all_bb_hit = capture_log(command, logname, file)

        # bb_hit = filter(bb_hit, bb_map)

        global_hit = merge_hit(global_hit, binary_bb_hit)
        result[file] = dict()
        result[file]['coverage'], result[file]['hit_in_ida'] = statistic(binary_bb_hit, bb_map)
        result[file]['binary_bb'] = len(binary_bb_hit)
        result[file]['non_binary_bb'] = len(all_bb_hit) - len(binary_bb_hit)
        result[file]['total_bb'] = len(all_bb_hit)

    print "Result"
    print "Total Basic Blocks: " + str(len(bb_map))
    print "==========================================="
    for file, res in sorted(result.iteritems()):
        print file + ":"
        print 'total executed bb: ' + str(res['total_bb'])
        print 'bb in binary: ' + str(res['binary_bb'])
        print 'bb in binary AND in bb addrs lifted by ida: ' + str(res['hit_in_ida'])
        print 'bb not in binary: ' + str(res['non_binary_bb'])

        print 'coverage: ' + str(res['coverage']) + '%'
        print '\n'
    print "==========================================="
    overall_coverage, overall_hit = statistic(global_hit, bb_map)
    print "total bb hit in binary AND bb addres lifted by ida: " + str(overall_hit)
    print "Overall coverage: " + str(overall_coverage) + '%'

if __name__ == '__main__':
    main()
