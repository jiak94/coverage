import shlex
import psutil
import subprocess
import sys
import os
import time
import hashlib
from datetime import datetime
import json


def json_load(file_handle):
        return _byteify(
            json.load(file_handle, object_hook=_byteify))


def _byteify(data, ignore_dicts=True):
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


class Coverage:

    binary_overall_hit = list()
    so_overall_hit = dict()
    lib_addr_dict = dict()
    bb_list = list()
    usermode_command = ''
    config = dict()

    def capture_bb(self, filename):
        with open(filename, 'r') as bb_file:
            bb_list = bb_file.readlines()

        bb_list = [x.strip() for x in bb_list]
        return bb_list


    def calculate_lib_offset(self, maps, lib_addr):
        res = dict()
        for lib in self.lib_list:
            try:
                base_addr = maps[lib][0]
                base_addr = int(base_addr, 16)
                res[lib] = list()

                for addr in lib_addr[lib]:
                    res[lib].append(hex(int(addr, 16) - base_addr))

                res[lib] = list(set(res[lib]))
            except BaseException:
                pass

        return res


    def capture_log(self, program_exec_command, logname, testcase, lib_list):
        command = self.usermode_command + " " + logname + \
            " " + "-b " + " ".join(program_exec_command)

        proc = subprocess.Popen(shlex.split(command),
                                shell=False,
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE)

        p = psutil.Process(proc.pid)

        while (p.status() is 'running'):
            time.sleep(1)

        mem_map = self.get_mem_mapping(proc.pid)

        # try to resume process
        p.resume()

        # resume fail, kill that process, then execute again without pause
        if p.status is not 'running':
            p.kill()
            command = self.usermode_command + " " + logname + \
                " " + " ".join(program_exec_command)
            proc = subprocess.Popen(shlex.split(command),
                                    shell=False,
                                    stderr=subprocess.PIPE,
                                    stdout=subprocess.PIPE)
            proc.wait()

        stderr = proc.stderr.read()

        # write log if any std err return
        if len(stderr) is not 0:
            print "Error occurs while executing %s" % str(testcase)
            print "Program or Qemu crashed, please check error log for more information"
            self.write_error_log(testcase, stderr)

        binary_bb_hit, libs_bb_hit = self.process_trace(logname, mem_map)

        return binary_bb_hit, libs_bb_hit


    def process_trace(self, logname, maps):
        binary_bb_hit = list()
        libs_bb_hit = dict()

        for key, val in maps.iteritems():
            libs_bb_hit[key] = list()

        with open(logname, 'r') as log:
            lines = log.readlines()

        for line in lines:
            if 'Trace' in line:
                line = "0x" + line[line.find('[') + 1: line.rfind(']')].lstrip("0")

                if int(line, 16) >= int(self.start_code, 16) and int(line, 16) < int(self.end_code, 16):
                    binary_bb_hit.append(line)
                else:
                    for key, val in maps.iteritems():
                        try:
                            if int(
                                    line, 16) >= int(
                                    val[0],
                                    16) and int(
                                    line, 16) < int(
                                    val[1],
                                    16):
                                libs_bb_hit[key].append(line)
                                break
                        except BaseException:
                            pass

        libs_bb_hit = self.calculate_lib_offset(maps, libs_bb_hit)

        testcase_name = logname[logname.rfind('/')+1:]
        testcase_name = testcase_name[testcase_name.find(
            '.')+1:testcase_name.rfind('.')]
        hash_object = hashlib.md5(testcase_name)

        filename = datetime.now().strftime(
            self.result_folder + "bin_" + hash_object.hexdigest())
        with open(filename, 'a+') as f:
            for line in binary_bb_hit:
                f.write(line)
                f.write('\n')

        for key, val in libs_bb_hit.iteritems():
            filename = datetime.now().strftime(
                self.result_folder + key + '_'+hash_object.hexdigest())
            with open(filename, 'a+') as f:
                for line in val:
                    f.write(line)
                    f.write('\n')

        return list(set(binary_bb_hit)), libs_bb_hit


    def correct_static_analysis(self, hit_list, bb_list):
        for addr in hit_list:
            if addr not in bb_list:
                # hit_list.remove(addr)
                bb_list.append(addr)

        hit_list = list(set(hit_list))

        return bb_list


    def statistic(self, hit_list, bb_list):
        return (len(hit_list)/float(len(bb_list))) * 100


    def merge_hit(self, hit_list, so=False, name=None):
        if so:
            if name is None:
                return
            else:
                for addr in hit_list:
                    if addr not in self.so_overall_hit[name]:
                        self.so_overall_hit[name].append(addr)

            self.so_overall_hit[name] = list(set(self.so_overall_hit[name]))
            return
        for addr in hit_list:
            if addr not in self.binary_overall_hit:
                self.binary_overall_hit.append(addr)


    def write_error_log(self, testcase, error_meg):
        error_folder = "error/"
        if not os.path.exists(error_folder):
            os.makedirs(error_folder)

        logname = datetime.now().strftime(testcase + '_error_%m-%d_%H:%M:%S')
        f = open(error_folder + logname, 'a+')
        f.write(error_meg + '\n')
        f.close()


    def get_mem_mapping(self, pid):
        res = dict()
        command = "pmap " + str(pid)

        proc = subprocess.Popen(
            shlex.split(command),
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
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
        for lib in self.lib_list:
            res[lib] = list()
            for line in format_stdout:
                try:
                    if 'x' in line[2] and lib == line[3]:
                        start = "0x"+line[0]
                        size = line[1][:-1]

                        res[lib].append(start)
                        res[lib].append(self.calculate(start, int(size)))
                        break
                except BaseException:
                    pass
        # import IPython;IPython.embed()
        for line in format_stdout:
            if 'x' in line[2] and line[3] in self.program:
                self.start_code = "0x"+line[0]
                size = line[1][:-1]
                self.end_code = self.calculate(self.start_code, int(size))
                break

        return res


    def calculate(self, start, size):
        return hex(int(start, 16) + 1024 * size)


    def __init__(self, config_file):
        if 'QEMU' not in os.environ:
            print "Please set QEMU binary root. export QEMU=qemu_bin"
            sys.exit(2)
        configuration = None
        with open(config_file) as con:
            configuration = json_load(con)

        # Load configuration
        self.lib_list = configuration['library']
        self.file_input = configuration['file_input']
        self.program = configuration['target_binary']
        self.program_option = " ".join(configuration['target_option'])
        self.save_result = configuration['save_result']
        self.with_statistic = configuration['show_statistic']
        self.test_object = configuration['test_object']

        self.usermode_command = os.environ['QEMU'] + '/qemu-x86_64 -d exec -D '

        # Set up a log/result folder for certain binary
        self.result_folder = self.program[self.program.rfind('/')+1:] + "_result/"
        self.log_folder = self.program + "_trace/"

        if not os.path.exists(self.log_folder):
            os.makedirs(self.log_folder)

        if not os.path.exists(self.result_folder):
            os.makedirs(self.result_folder)

        # read in static analysis result
        if self.with_statistic:
            addr_filename = self.program + '_addr'
            self.bb_list = self.capture_bb(addr_filename)

            for lib in self.lib_list:
                with open(lib+"_addr", 'r') as f:
                    addr = f.readlines()
                self.lib_addr_dict[lib] = addr

        # Initialize the so_overall_hit dictionary
        for item in self.lib_list:
            self.so_overall_hit[item] = list()


    def check_coverage(self, file):
        command = list()
        command.append(self.program)
        if self.file_input:
            command.append(self.program_option)
            command.append(file)

        else:
            with open(file) as testcase_file:
                data = testcase_file.read().replace('\n', '')
            command.append(data)

        logname = self.log_folder + self.program + '.' + file + '.log'

        binary_bb_hit, libs_bb_hit = self.capture_log(
            command, logname, file, self.lib_list)

        # adjust the static analysis bb count
        if self.with_statistic:
            self.bb_list = self.correct_static_analysis(binary_bb_hit, self.bb_list)
            for key, val in libs_bb_hit.iteritems():
                self.lib_addr_dict[key] = self.correct_static_analysis(
                    val, self.lib_addr_dict[key])

        # Update binary_overall_hit
        self.merge_hit(binary_bb_hit)

        result = dict()
        result['testcase'] = file
        result['binary_bb_hit'] = binary_bb_hit
        result['bb_list'] = self.bb_list
        result['libs_bb_list'] = self.lib_addr_dict
        result['libs_bb_hit'] = libs_bb_hit

        return result


    def pretty_print(self, result):
        if self.with_statistic:
            # print "Total Basic Blocks: " + str(len(result['bb_list']))
            # print "==========================================="

            print "Testcase: %s " % file.name
            print "--Binary Hits: %d" % len(result['binary_bb_hit'])

            if self.with_statistic:
                if self.test_object is 1 or self.test_object is 0:
                    coverage = self.statistic(result['binary_bb_hit'], self.bb_list)
                    print 'Coverage: %s' % str(coverage)

            if self.test_object is 0 or self.test_object is 2:
                for lib in self.lib_list:
                    self.merge_hit(result['libs_bb_hit'][lib], True, lib)
                    print "-- %s Hits: %d" % (lib, len(result['libs_bb_hit'][lib]))

                    if self.with_statistic:
                        so_coverage = self.statistic(
                            result['libs_bb_hit'][lib], self.lib_addr_dict[lib])
                        print "%s coverage: %s" % (lib, str(so_coverage))


    def pretty_print_overall(self):
        if self.with_statistic:
            overall_coverage = self.statistic(self.binary_overall_hit, self.bb_list)
            print "Overall coverage: %s" % str(overall_coverage)
            print "Adjusted Total Basic Blocks: %d" % len(self.bb_list)
        print "Binary Overall hit: %d" +  len(self.binary_overall_hit)


    # def main():
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


    def save_result(self):
        logname = self.result_folder + datetime.now().strftime(
            self.program[self.program.rfind('/')+1:] + '_overall_%m-%d_%H:%M:%S')
        f = open(logname, "a+")
        for addr in binary_overall_hit:
            f.write(addr)
            f.write('\n')
        f.close()
        for key, val in self.so_overall_hit.iteritems():
            logname = self.result_folder + datetime.now().strftime(key + "_overall_%m-%d_%H:%M:%S")
            f = open(logname, "a+")
            for addr in val:
                f.write(addr)
                f.write('\n')
            f.close()


    # def json_load(self, file_handle):
    #     return self._byteify(
    #         json.load(file_handle, object_hook=self._byteify))


    # def _byteify(data, ignore_dicts=True):
    #     if isinstance(data, unicode):
    #         return data.encode('utf-8')
    #     if isinstance(data, list):
    #         return [_byteify(item, ignore_dicts=True) for item in data]
    #     if isinstance(data, dict) and not ignore_dicts:
    #         return {
    #             _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
    #             for key, value in data.iteritems()
    #         }
    #     return data


# if __name__ == '__main__':
    # main()
