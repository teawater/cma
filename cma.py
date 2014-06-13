#!/usr/bin/python
# -*- coding: utf-8 -*-

import gdb
import os, signal, ConfigParser, time, signal, re

class Lang(object):
    '''Language class.'''
    def __init__(self, language="en"):
        self.data = {}
        self.language = language
        self.is_set = False
        self.add("Please Input the file for record info:[%s]",
                 "请输入记录信息的文件名:[%s]")
        self.add('Cannot write "%s".',
                 '不能写"%s".')
        self.add("Record the infomation of released memory?",
                 "记录释放掉的内存的信息？")
        self.add("Record backtrace infomation?",
                 "记录backtrace信息？")
        self.add("Type",
                 "类型")
        self.add("Address",
                 "地址")
        self.add("Size",
                 "长度")
        self.add("Existence time(sec)",
                 "存在时间(秒)")
        self.add("Allocate line",
                 "分配行")
        self.add("Release line",
                 "释放行")
        self.add("Allocate backtrace",
                 "分配backtrace")
        self.add("Release backtrace",
                 "释放backtrace")
        self.add('Record memory infomation to "%s".',
                 '记录内存信息到“%s”。')
        self.add("Continue.",
                 "继续。")
        self.add('Quit.',
                 '退出。')
        self.add("Which operation?",
                 "哪个操作？")
        self.add("Inferior exec failed:",
                 "被调试程序执行出错：")
        self.add('Memory infomation saved into "%s".',
                 '内存信息存入“%s”。')
        self.add('File for record info is "%s".',
                 '记录文件是“%s”。')
        self.add('Script will record infomation of released memory.',
                 '脚本将记录已经被释放掉的内存信息。')
        self.add('Script will not record infomation of released memory.',
                 '脚本将不记录已经被释放掉的内存信息。')
        self.add('Script will backtrace infomation.',
                 '脚本将记录backtrace信息。')
        self.add('Script will not backtrace infomation.',
                 '脚本将不记录backtrace信息。')
        self.add("Which memory function do you want to record?",
                 "记录哪个内存函数？")
        self.add('Script will record memory function "%s".',
                 '脚本将记录内存函数“%s”。')

    def set_language(self, language):
        if language != "":
            if language[0] == "e" or language[0] == "E":
                self.language = "en"
            else:
                self.language = "cn"
            self.is_set = True

    def add(self, en, cn):
        self.data[en] = cn

    def string(self, s):
        if self.language == "en" or (not self.data.has_key(s)):
            return s
        return self.data[s]

def yes_no(string="", has_default=False, default_answer=True):
    if has_default:
        if default_answer:
            default_str = " [Yes]/No:"
        else:
            default_str = " Yes/[No]:"
    else:
        default_str = " Yes/No:"
    while True:
        s = raw_input(string + default_str)
        if len(s) == 0:
            if has_default:
                return default_answer
            continue
        if s[0] == "n" or s[0] == "N":
            return False
        if s[0] == "y" or s[0] == "Y":
            return True

def select_from_list(entry_list, default_entry, introduction):
    if type(entry_list) == dict:
        entry_dict = entry_list
        entry_list = list(entry_dict.keys())
        entry_is_dict = True
    else:
        entry_is_dict = False
    while True:
        default = -1
        default_str = ""
        for i in range(0, len(entry_list)):
            if entry_is_dict:
                print("[%d] %s %s" %(i, entry_list[i], entry_dict[entry_list[i]]))
            else:
                print("[%d] %s" %(i, entry_list[i]))
            if default_entry != "" and entry_list[i] == default_entry:
                default = i
                default_str = "[%d]" %i
        try:
            select = input(introduction + default_str)
        except SyntaxError:
            select = default
        except Exception:
            select = -1
        if select >= 0 and select < len(entry_list):
            break
    return entry_list[select]

def config_write():
    fp = open(config_dir, "w+")
    Config.write(fp)
    fp.close()

def config_check_show(section, option, callback, show1=None, show2=None):
    if not Config.has_section(section):
        Config.add_section(section)
    if not Config.has_option(section, option):
        Config.set(section, option, callback())
    else:
        if show2 == None:
            print (show1 %Config.get(section, option))
        else:
            if Config.get(section, option) == "True":
                print show1
            else:
                print show2

def record_save():
    # File format:
    # new/malloc, addr, size, existence time, allocate line, release line, [allocate bt, release bt]
    f = open(record_dir, "w")
    f.write(file_header)
    cur = time.time()

    for addr in no_released:
        line = "'%s', '0x%x', '%d', '%f', '%s', ''" %("new" if no_released[addr][3] else "malloc", addr, no_released[addr][0], cur - no_released[addr][2], no_released[addr][1])
        if record_bt:
            line += ", '%s', ''" %no_released[addr][4]
        line += "\n"
        f.write(line)

    f.write("\n")

    for e in released:
        line = "'%s', '0x%x', '%d', '%f', '%s', '%s'" %("new" if e[5] else "malloc", e[0], e[1], e[4], e[2], e[3])
        if record_bt:
            line += ", '%s', '%s'" %(e[6], e[7])
        line += "\n"
        f.write(line)
    f.close()
    print(lang.string('Memory infomation saved into "%s".') %record_dir)

def function_is_available(fun):
    s = gdb.execute("b " + fun, False, True)
    error_s = 'Function "' + fun + '" not defined.'
    if s[:len(error_s)] == error_s:
        return False
    return True

class arch_x86_32(object):
    def is_current():
        if gdb.execute("info reg", True, True).find("eax") >= 0:
            return True
        return False
    def get_arg1():
        return long(gdb.parse_and_eval("*(unsigned long *)($ebp+8)"))
    def get_ret():
        return long(gdb.parse_and_eval("$eax"))

class arch_x86_64(object):
    def is_current():
        if gdb.execute("info reg", True, True).find("rax") >= 0:
            return True
        return False
    def get_arg1():
        return long(gdb.parse_and_eval("$rdi"))
    def get_ret():
        return long(gdb.parse_and_eval("$rax"))

archs = (arch_x86_32, arch_x86_64)

# Do "start" if need.
try:
    gdb.execute("info reg", True, True)
except gdb.error, x:
    gdb.execute("start", True, True)

# Get arch.
for e in archs:
    arch = e()
    if arch.is_current():
        break
else:
    raise Exception("Current architecture is not supported by CMA.")

# Check if current application has malloc and new.
have_malloc = function_is_available("malloc")
have_new = function_is_available("operator new")
if not have_malloc and not have_new:
    raise Exception("Inferior doesn't have new and malloc.")

# Clear old breakppints.
gdb.execute("delete")

# Load config
default_config_dir = os.path.realpath("./cma.conf")
config_dir = raw_input("Please Input the config file:[" + default_config_dir + "]")
if len(config_dir) == 0:
    config_dir = default_config_dir
Config = ConfigParser.ConfigParser()
try:
    Config.read(config_dir)
except Exception, x:
    try:
        config_write()
    except:
        print("Cannot write config file.")
        exit(-1)
# misc language
def get_language_callback():
    return select_from_list(("English", "Chinese"), "", "Which language do you want to use?")
config_check_show("misc", "language", get_language_callback, "Language is set to %s.")
lang = Lang()
lang.set_language(Config.get("misc", "language"))
# misc record_dir
def get_record_dir_callback():
    default = os.path.realpath("./cma.csv")
    while True:
        ret = raw_input(lang.string("Please Input the file for record info:[%s]") %default)
        if len(ret) == 0:
            ret = default
        ret = os.path.realpath(ret)
        try:
            file(ret, "w")
        except:
            print(lang.string('Cannot write "%s".') %ret)
            continue
        break
    return ret
config_check_show("misc", "record_dir", get_record_dir_callback, lang.string('File for record info is "%s".'))
record_dir = Config.get("misc", "record_dir")
# misc record_released
def get_record_released_callback():
    return str(yes_no(lang.string("Record the infomation of released memory?")))
config_check_show("misc", "record_released", get_record_released_callback, lang.string('Script will record infomation of released memory.'), lang.string('Script will not record infomation of released memory.'))
record_released = bool(Config.get("misc", "record_released"))
# misc record_bt
def get_record_bt_callback():
    return str(yes_no(lang.string("Record backtrace infomation?")))
config_check_show("misc", "record_bt", get_record_bt_callback, lang.string('Script will backtrace infomation.'), lang.string('Script will not backtrace infomation.'))
record_bt = bool(Config.get("misc", "record_bt"))
config_write()

# Get memory_function.
# 0 malloc
# 1 new
# 2 malloc and new
if have_malloc and have_new:
    m = select_from_list(("malloc/free and new/delete", "malloc/free", "new/delete"), "", lang.string("Which memory function do you want to record?"))
    if m == "malloc/free and new/delete":
        memory_function = 2
    elif m == "malloc/free":
        memory_function = 0
    else:
        memory_function = 1
elif have_malloc:
    memory_function = 0
    print(lang.string('Script will record memory function "%s".') %"malloc/free")
else:
    memory_function = 1
    print(lang.string('Script will record memory function "%s".') %"new/delete")

gdb.execute("set pagination off", False, False)

run = True

# Format: size, line, time, is_new, [bt]
no_released = {}
# Format: addr, size, allocate_line, release_line, time, is_new, [allocate_bt, release_bt]
released = []

file_header = "'" + lang.string("Type") + "', '" + lang.string("Address") + "', '" + lang.string("Size") + "', '" + lang.string("Existence time(sec)") + "', '" + lang.string("Allocate line") + "', '" + lang.string("Release line") + "'"
if record_bt:
    file_header += ", '" + lang.string("Allocate backtrace") + "', '" + lang.string("Release backtrace") + "'"
file_header += "\n"

s_operations = (lang.string('Record memory infomation to "%s".') %record_dir,
                lang.string("Continue."),
                lang.string('Quit.'))

def sigint_handler(num=None, e=None):
    global run
    a = select_from_list(s_operations, s_operations[0], lang.string("Which operation?"))
    if a == s_operations[0]:
        record_save()
    elif a == s_operations[2]:
        run = False

def inferior_sig_handler(event):
    if type(event) == gdb.SignalEvent and str(event.stop_signal) == "SIGINT":
        sigint_handler()

signal.signal(signal.SIGINT, sigint_handler);
signal.siginterrupt(signal.SIGINT, False);

gdb.events.stop.connect(inferior_sig_handler)

# Setup breakpoint
if memory_function == 0 or memory_function == 2:
    gdb.execute("b malloc", False, False)
    gdb.execute("b free", False, False)
if memory_function == 1 or memory_function == 2:
    gdb.execute("b operator new", False, False)
    gdb.execute("b operator delete", False, False)

while run:
    try:
        gdb.execute("continue", True)
        s = str(gdb.parse_and_eval("$pc"))
    except gdb.error, x:
        print(lang.string("Inferior exec failed:"), x)
        break

    r = re.search(r'(<malloc>|<free>|<operator new\(|<operator delete\()', s)
    if not bool(r):
        continue
    r = r.group(1)

    if memory_function == 0 or memory_function == 2:
        if r == "<malloc>":
            is_alloc = True
            is_new = False
        elif r == "<free>":
            is_alloc = False
            is_new = False
    if memory_function == 1 or memory_function == 2:
        if r == "<operator new(":
            is_alloc = True
            is_new = True
        elif r == "<operator delete(":
            is_alloc = False
            is_new = True

    if is_alloc:
        # alloc size
        size = arch.get_arg1()
        gdb.execute("disable", False, False)
        gdb.execute("finish", False, True)
        gdb.execute("enable", False, False)
        # alloc addr
        addr = arch.get_ret()
        # alloc size
        no_released[addr] = []
        no_released[addr].append(size)
        # alloc line
        no_released[addr].append(str(gdb.execute("info line", True, True)).strip())
        # alloc bt to bt
        if record_bt:
            bt = str(gdb.execute("backtrace", True, True)).strip()
        no_released[addr].append(time.time())
        no_released[addr].append(is_new)
        if record_bt:
            no_released[addr].append(bt)
    else:
        # release addr
        addr = arch.get_arg1()
        if addr in no_released:
            if record_released:
                cur_time = time.time()
                gdb.execute("up", False, True)
                # addr, size, allocate_line, release_line, time
                add = [addr, no_released[addr][0], no_released[addr][1], str(gdb.execute("info line", True, True)).strip(), cur_time - no_released[addr][2], no_released[addr][3]]
                # bt
                if record_bt:
                    add.append(no_released[addr][4])
                    add.append(str(gdb.execute("backtrace", True, True)).strip())
                released.append(add)
                gdb.execute("down", False, True)
            del no_released[addr]
        gdb.execute("disable", False, False)
        gdb.execute("finish", False, True)
        gdb.execute("enable", False, False)

record_save()
