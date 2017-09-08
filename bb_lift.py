import idaapi
import idautils
import idc

def analysis():
    all_funcs = idautils.Functions()
    overall_addr = list()

    print all_funcs
    for f in all_funcs:
        print f, hex(f)
        print "In %s:\n"%(idc.GetFunctionName(f),)

        f = idaapi.FlowChart(idaapi.get_func(f),flags=idaapi.FC_PREDS)

        for block in f:
            overall_addr.append(hex(block.startEA))

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
