import idaapi
import idautils
import idc

def analysis():
    all_funcs = idautils.Functions()
    overall_addr = list()

    # addr_overall = open('addr_overall', 'a+')
    # addr_bin = open('addr_bin', 'a+')

    # addr_lib = open('addr_lib', 'a+')
    print all_funcs
    for f in all_funcs:
        print f, hex(f)
        print "In %s:\n"%(idc.GetFunctionName(f),)


        # fflags = idc.GetFunctionFlags(f)
        # print type(fflags)
        # print fflags

        f = idaapi.FlowChart(idaapi.get_func(f),flags=idaapi.FC_PREDS)

        for block in f:
            # addr_overall.write(hex(block.startEA))
            # addr_overall.write('\n')
            overall_addr.append(hex(block.startEA))

            # if fflags == FUNC_LIB:
            #     # addr_lib.write(hex(block.startEA))
            #     # addr_lib.write('\n')
            #     lib_addr.append(hex(block.startEA))
            # else:
            #     # addr_bin.write(hex(block.startEA))
            #     # addr_bin.write('\n')
            #     bin_addr.append(hex(block.startEA))
    filename = idc.GetInputFile() + "_addr"
    with open(filename, 'a+') as f:
        for item in overall_addr:
            f.write(item)
            f.write('\n')

def main():
    analysis()
    print "Dumping Basic Block Address Done!"
if __name__ == "__main__":
    main()
