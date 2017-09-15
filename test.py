import coverage

config = open('./readelf.json')
tool = coverage.Coverage(config)

result = tool.check_coverage('./testcases/readelf')

tool.pretty_print(result)
