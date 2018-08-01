#import lang_specific
from os_specific import *
from Scan import Scan

from collections import defaultdict


class ScanDockerFile(Scan):

    def __init__(self, file):
        self.file = file
    
    def get_instr(self):
        lines = self.file.readlines()
        # exclude comments
        lines = [x for x in lines if not x.startswith('#')]
        # exclude newline characters
        lines = [x for x in lines if x != '\n']
        new_lines = []
        temp_str = ''
        # cleaning
        for i in lines:
            if i[-2] == "\\":
                i = i.rstrip()
                temp_str = temp_str + i[:-1]
            if i[-1] != "\\":
                temp_str = temp_str + i
                new_lines.append(temp_str.rstrip())
                temp_str = ''
        new_lines = [x.rstrip() for x in new_lines]
        new_lines = [' '.join(x.split()) for x in new_lines]
        keys = defaultdict(list)
        for t in new_lines:
        	key = t.split()[0]
        	value = ' '.join(t.split()[1:]).split(';')
        	value = [x for x in value if x != '']
        	keys[key].append(value)
        return keys

    def get_keys(self):
        instr_dict = self.get_instr()
        libs = [] #list of tuples <package,version>
        inst_from = instr_dict['FROM']
        for inst in inst_from:
            inst = inst[0].split(' ',1)[0]
            inst = inst.split(':')
            libs.append([inst[0],inst[1]])
        images = find_base_images(instr_dict)
        for i in images:
            libs += name_version(instr_dict, i)
        return libs


    def get_ADD(self, instr_dict):
        reg_url = r'^(?:http(?:s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)(?:[\S]+)$'
        src_url = []
        if 'ADD' in instr_dict:
            add = instr_dict['ADD']
            for i in add:
                src = i[0].split()[0]
                p = re.compile(reg_url)
                match = p.match(src)
                if match:
                    src_url.append(src)

        return src_url


    def get_user(self, instr_dict):
        if 'USER' in instr_dict:
            return 'USER Present'
        else:
            return 'Warning! Root access to USER.'


if __name__ == '__main__':
    with open('Dockerfile') as file:
        test_scan = ScanDockerFile(file)
        dic = test_scan.get_instr()
        keys = test_scan.get_keys(dic)
        print(test_scan.get_user(dic))
        #print dic.keys()
        print(test_scan.get_ADD(dic))