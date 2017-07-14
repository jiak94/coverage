import matplotlib.pyplot as plt
import collections
import numpy as np

def capture_result(report):
    with open(report, 'r') as f:
        res = f.readlines()

    return res

def classify_result(result_files):
    res = dict()

    for file in result_files:
        filename = file[file.rfind('/')+1:file.find('_coverage')]

        if res.has_key(filename):
            res[filename].append(file)
        else:
            res[filename] = list()
            res[filename].append(file)

    return res

# parse multiple result file
def parse_results(result, basic_blocks):
    res = dict()

    previous_list = list()
    for file in sorted(result):
        hit_count, new_hit = parse_result(file, previous_list)
        key = file[file.rfind('coverage_') + 9:]
        res[key] = hit_count/float(len(basic_blocks)) * 100
        previous_list += new_hit
        previous_list = list(set(previous_list))
        res = collections.OrderedDict(sorted(res.items()))
        print res
        print len(previous_list)

    return res

# parse a single result file
def parse_result(file, previous_list):
    addrs = previous_list
    with open(file, 'r') as f:
        addr = f.readlines()
    addrs += addr
    addrs = list(set(addrs))
    return len(addrs), addrs

def generate_report(log_dict, title):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    plt.title(title)
    plt.ylim(0, 100)
    plt.ylabel('Coverage')
    plt.xlabel('Date')

    plt.margins(0.1, 0.1)

    count = 0
    x = list()
    y = list()
    x_sticker = list()

    log_dict = collections.OrderedDict(sorted(log_dict.items()))

    for key, val in log_dict.iteritems():
        x.append(count)
        count += 1
        y.append(val)
        x_sticker.append(key)

    # fig, ax = plt.subplots(1, 1)

    plt.xticks(np.arange(len(log_dict)), x_sticker, rotation=90)
    plt.plot(y)

    for xy in zip(x, y):
        ax.annotate('%.2f' % xy[1], xy=xy, textcoords='data')

    plt.show()

test = {'a':22, 'b':33, 'c':44}
# generate_report(test)

