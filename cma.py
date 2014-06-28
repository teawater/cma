#!/usr/bin/python
# -*- coding: utf-8 -*-

import gdb
import os, signal, ConfigParser, time, signal, re

#-----------------------------------------------------------------------
# The language class
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
        self.add('Quit and record memory infomation to "%s".',
                 '退出并记录内存信息到“%s”。')
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
        self.add("Do you want to record memory function malloc/calloc/realloc/free?",
                 '是否记录内存函数malloc/calloc/realloc/free？')
        self.add("Do you want to record memory function new/delete?",
                 '是否记录内存函数new/delete？')
        self.add("Do you want to record memory function kmalloc/kfree?",
                 '是否记录内存函数kmalloc/kfree？')
        self.add("Cannot find any dynamic memory allocate functions.",
                 "无法找到任何动态内存分配函数。")

    def set_language(self, language):
        if language != "":
            if language[0] == "c" or language[0] == "C":
                self.language = "cn"
            else:
                self.language = "en"
            self.is_set = True

    def add(self, en, cn):
        self.data[en] = cn

    def string(self, s):
        if self.language == "en" or (not self.data.has_key(s)):
            return s
        return self.data[s]

#-----------------------------------------------------------------------
# The UI functions
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
#-----------------------------------------------------------------------
# The config functions
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
#-----------------------------------------------------------------------
def get_info_line(current):
    ret = ""
    is_first_loop = True
    while True:
        if current and is_first_loop:
            is_first_loop = False
        else:
            try:
                gdb.execute("up", False, True)
            except gdb.error:
                raise Exception
                if ret != "":
                    break
        s = str(gdb.execute("info line *$pc", True, True)).strip()
        error_s = 'No line number information available'
        if s[:len(error_s)] != error_s:
            ret = s
            break
        if ret == "":
            ret = s
    gdb.execute("frame 0", False, True)
    return ret
#-----------------------------------------------------------------------
# Functions about record file
def record_save():
    # File format:
    # type, addr, size, existence time, allocate line, release line, [allocate bt, release bt]
    f = open(record_dir, "w")
    f.write(file_header)
    cur = time.time()

    for addr in not_released:
        line = "'%s', '0x%x', '%d', '%f', '%s', ''" %(not_released[addr][3], addr, not_released[addr][0], cur - not_released[addr][2], not_released[addr][1])
        if record_bt:
            line += ", '%s', ''" %not_released[addr][4]
        line += "\n"
        f.write(line)

    f.write("\n")

    for e in released:
        line = "'%s', '0x%x', '%d', '%f', '%s', '%s'" %(e[5], e[0], e[1], e[4], e[2], e[3])
        if record_bt:
            line += ", '%s', '%s'" %(e[6], e[7])
        line += "\n"
        f.write(line)
    f.close()
    print(lang.string('Memory infomation saved into "%s".') %record_dir)

def file_header_init():
    global file_header
    file_header = "'" + lang.string("Type") + "', '" + lang.string("Address") + "', '" + lang.string("Size") + "', '" + lang.string("Existence time(sec)") + "', '" + lang.string("Allocate line") + "', '" + lang.string("Release line") + "'"
    if record_bt:
        file_header += ", '" + lang.string("Allocate backtrace") + "', '" + lang.string("Release backtrace") + "'"
    file_header += "\n"

# Format: size, line, time, memtype, [bt]
not_released = {}

def not_released_add(addr, size, memtype, line=None, bt=None):
    global not_released

    if addr == 0:
        return

    if addr in not_released:
        if line == None:
            line = get_info_line(True)
        if bt == None:
            bt = str(gdb.execute("backtrace", True, True)).strip()
        print(lang.string("Error in not_released_add addr 0x%x old: %s new: %d, %s, %s, %s.  Please report this message to https://github.com/teawater/cma/issues/.") %(addr, not_released[addr], size, memtype, line, bt))

    not_released[addr] = []
    not_released[addr].append(size)
    if line == None:
        not_released[addr].append(get_info_line(True))
    else:
        not_released[addr].append(line)
    if record_bt and bt == None:
        bt = str(gdb.execute("backtrace", True, True)).strip()
    not_released[addr].append(time.time())
    not_released[addr].append(memtype)
    if record_bt:
        not_released[addr].append(bt)

# Format: addr, size, allocate_line, release_line, time, memtype, [allocate_bt, release_bt]
released = []

def released_add(addr, memtype, line=None, bt=None):
    global not_released, released

    if addr == 0:
        return

    if addr in not_released:
        if record_released:
            cur_time = time.time()
            if line == None:
                line = get_info_line(False)

            if not_released[addr][3] != memtype:
                if bt == None:
                    bt = str(gdb.execute("backtrace", True, True)).strip()
                print(lang.string("Error in released_add addr 0x%x old: %s new: %s, %s, %s.  Please report this message to https://github.com/teawater/cma/issues/.") %(addr, not_released[addr], memtype, line, bt))
                return

            add = [addr, not_released[addr][0], not_released[addr][1], line, cur_time - not_released[addr][2], not_released[addr][3]]
            if record_bt:
                add.append(not_released[addr][4])
                if bt == None:
                    add.append(str(gdb.execute("backtrace", True, True)).strip())
                else:
                    add.append(bt)
            released.append(add)
        del not_released[addr]

#-----------------------------------------------------------------------
# Functions about signal
def sigint_handler(num=None, e=None):
    global run

    s_operations = (lang.string('Record memory infomation to "%s".') %record_dir,
                    lang.string("Continue."),
                    lang.string('Quit and record memory infomation to "%s".') %record_dir)
    a = select_from_list(s_operations, s_operations[0], lang.string("Which operation?"))
    if a == s_operations[0]:
        record_save()
    elif a == s_operations[2]:
        run = False

def inferior_sig_handler(event):
    if type(event) == gdb.SignalEvent and str(event.stop_signal) == "SIGINT":
        sigint_handler()
#-----------------------------------------------------------------------
#Archs
class arch_x86_32(object):
    def is_current(self):
        if gdb.execute("info reg", True, True).find("eax") >= 0:
            return True
        return False
    def get_arg(self, num):
        if num > 1:
            raise Exception("get_arg %d is not supported." %num)
        gdb.execute("up", False, True)
        ret = long(gdb.parse_and_eval("*(unsigned int *)($esp + " + str(num * 4) + ")"))
        gdb.execute("down", False, True)
        return ret
    def get_ret(self):
        return long(gdb.parse_and_eval("$eax"))

class arch_x86_64(object):
    def is_current(self):
        if gdb.execute("info reg", True, True).find("rax") >= 0:
            return True
        return False
    def get_arg(self, num):
        if num == 0:
            return long(gdb.parse_and_eval("$rdi"))
        elif num == 1:
            return long(gdb.parse_and_eval("$rsi"))
        else:
            raise Exception("get_arg %d is not supported." %num)
    def get_ret(self):
        return long(gdb.parse_and_eval("$rax"))

archs = (arch_x86_32, arch_x86_64)

#-----------------------------------------------------------------------
# The Break class
class BreakException(Exception):
    pass

class Break(object):
    def __init__(self, name, res=None, trigger=None, memtype=None):
        ''' name: The break command will set to it.
            res: Regular expression for the name to get the string about this break.  If None, it will set to "name".
            trigger: After regular expression, the string for this break.  If None, it will set to "res".
            memtype: The memory type for this break.  If None, it will set to "name".
        '''
        got_break = False
        s = gdb.execute("b " + name, False, True)
        error_s = 'Function "' + name + '" not defined.'
        if s[:len(error_s)] == error_s:
            raise BreakException

        self.name = name
        if res == None:
            self.res = name
        else:
            self.res = res
        if trigger == None:
            self.trigger = self.res
        else:
            self.trigger = trigger
        if memtype == None:
            self.memtype = name
        else:
            self.memtype = memtype

class Break_alloc(Break):
    def event(self):
        size = arch.get_arg(0)
        gdb.execute("disable", False, False)
        gdb.execute("finish", False, True)
        gdb.execute("enable", False, False)
        not_released_add(arch.get_ret(), size, self.memtype)

class Break_calloc(Break):
    def event(self):
        size = arch.get_arg(0) * arch.get_arg(1)
        gdb.execute("disable", False, False)
        gdb.execute("finish", False, True)
        gdb.execute("enable", False, False)
        not_released_add(arch.get_ret(), size, self.memtype)

class Break_realloc(Break):
    def event(self):
        released_add(arch.get_arg(0), self.memtype)
        size = arch.get_arg(1)
        gdb.execute("disable", False, False)
        gdb.execute("finish", False, True)
        gdb.execute("enable", False, False)
        not_released_add(arch.get_ret(), size, self.memtype)

class Break_release(Break):
    def event(self):
        released_add(arch.get_arg(0), self.memtype)
        gdb.execute("disable", False, False)
        gdb.execute("finish", False, True)
        gdb.execute("enable", False, False)

breaks = {}
breaks_re = ""

def breaks_init():
    global breaks, breaks_re

    while True:
        break_is_available = False

        # Clear old breakppints.
        gdb.execute("delete")

        try:
            b = Break_alloc("malloc", "<malloc")
        except BreakException:
            record_malloc = False
        else:
            break_is_available = True
            record_malloc = yes_no(lang.string("Do you want to record memory function malloc/calloc/realloc/free?"), True)
        if record_malloc:
            breaks[b.trigger] = b
            try:
                b = Break_calloc("calloc", "<calloc", memtype="malloc")
                breaks[b.trigger] = b
            except BreakException:
                pass
            try:
                b = Break_realloc("realloc", "<realloc", memtype="malloc")
                breaks[b.trigger] = b
            except BreakException:
                pass
            try:
                b = Break_release("free", "<free", memtype="malloc")
                breaks[b.trigger] = b
            except BreakException:
                pass

        try:
            b = Break_alloc("operator new", r'<operator new\(', '<operator new(', 'new')
        except BreakException:
            record_new = False
        else:
            break_is_available = True
            record_new = yes_no(lang.string("Do you want to record memory function new/delete?"), True)
        if record_new:
            breaks[b.trigger] = b
            try:
                b = Break_release("operator delete", r'<operator delete\(', '<operator delete(', 'new')
                breaks[b.trigger] = b
            except BreakException:
                pass

        try:
            b = Break_alloc("kmalloc", "<kmalloc")
        except BreakException:
            record_kmalloc = False
        else:
            break_is_available = True
            record_kmalloc = yes_no(lang.string("Do you want to record memory function kmalloc/kfree?"), True)
        if record_kmalloc:
            breaks[b.trigger] = b
            try:
                b = Break_release("kfree", "<kfree", memtype="kmalloc")
                breaks[b.trigger] = b
            except BreakException:
                pass

        if len(breaks) != 0:
            break

        if not break_is_available:
            raise Exception(lang.string("Cannot find any dynamic memory allocate functions."))

    breaks_re = "("
    for i in breaks:
        if breaks_re != "(":
            breaks_re += "|"
        breaks_re += breaks[i].res
    breaks_re += ")"
    breaks_re = re.compile(breaks_re)

#-----------------------------------------------------------------------
# Real main code

gdb.execute("set pagination off", False, False)

# Do "start" if need.
try:
    gdb.execute("info reg", True, True)
except gdb.error, x:
    gdb.execute("delete")
    gdb.execute("start", True, True)

# Get arch.
for e in archs:
    arch = e()
    if arch.is_current():
        break
else:
    raise Exception("Current architecture is not supported by CMA.")

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

file_header_init()

breaks_init()

run = True

# Setup signal handler
signal.signal(signal.SIGINT, sigint_handler)
signal.siginterrupt(signal.SIGINT, False)
gdb.events.stop.connect(inferior_sig_handler)

while run:
    try:
        gdb.execute("continue", True)
        s = str(gdb.parse_and_eval("$pc"))
    except gdb.error, x:
        if str(x) != 'No registers.':
            print(lang.string("Inferior exec failed:"), x)
        break

    r = breaks_re.search(s)
    if not bool(r):
        continue
    breaks[r.group(1)].event()

record_save()

gdb.events.stop.disconnect(inferior_sig_handler)
