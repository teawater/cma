#!/usr/bin/python
# -*- coding: utf-8 -*-

import gdb
import os, multiprocessing, signal, ConfigParser

class Lang(object):
    '''Language class.'''
    def __init__(self, language="en"):
        self.data = {}
        self.language = language
        self.is_set = False
        self.add('Call command "%s" failed. ',
                 '调用命令"%s"失败。 ')

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

run = True
def myHandler(signum, e):
    global run
    run = False

def config_write():
    fp = open(config_dir, "w+")
    Config.write(fp)
    fp.close()

def config_check(section, option, callback):
    if not Config.has_section(section):
	Config.add_section(section)
    if not Config.has_option(section, option):
	Config.set(section, option, callback())

no_deleted = {}
deleted = []

def analyzer_write():
    f = open(record_dir, w)
    f.write("'Address', 'Allocation line', ")
    if record_bt:
	f.write("'Allocation backtrace', ")
    f.write("'Release line', ")
    if record_bt:
	f.write("'Release backtrace', ")
    f.write("\n")
    for addr in no_deleted:
	f.write("'0x%x', '%s', " %(addr, no_deleted[addr]))
    f.close()

def analyzer():
    while True:
	mlist_c.acquire()
	if len(mlist) == 0:
		mlist_c.wait()
	e = mlist.pop()
	mlist_c.release()
        if e == "quit":
	    break
        if e[0]:
	    #new
	    if record_bt:
	        no_deleted[e[1]] = (e[2], e[3])
	    else:
	        no_deleted[e[1]] = e[2]
	else:
	    #delete
	    addr = e[1]
	    if addr in no_deleted:
		if record_released:
		    if record_bt:
		        add = (no_deleted[addr][0], no_deleted[addr][1], e[2], e[3])
		    else:
		        add = (no_deleted[addr], e[2])
		    deleted.append(add)
		del no_deleted[e[1]]

#Load config
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
#misc language
def get_language_callback():
    return select_from_list(("English", "Chinese"), "", "Which language do you want to use?")
config_check("misc", "language", get_language_callback)
lang = Lang()
lang.set_language(Config.get("misc", "language"))
#misc record_dir
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
config_check("misc", "record_dir", get_record_dir_callback)
record_dir = Config.get("misc", "record_dir")
#misc record_released
def get_record_released_callback():
    return str(yes_no(lang.string("Record the infomation of released memory?"), True, False))
config_check("misc", "record_released", get_record_released_callback)
record_released = bool(Config.get("misc", "record_released"))
#misc record_bt
def get_record_bt_callback():
    return str(yes_no(lang.string("Record backtrace infomation?"), True))
config_check("misc", "record_bt", get_record_bt_callback)
record_bt = bool(Config.get("misc", "record_bt"))
config_write()

gdb.execute("set pagination off", False, False)

manager = multiprocessing.Manager()
mlist = manager.list()
mlist_c = manager.Condition()
p = multiprocessing.Process(target=analyzer)
p.start()

#Setup breakpoint
gdb.execute("b operator new", False, False)
gdb.execute("b operator delete", False, False)

signal.signal(signal.SIGINT, myHandler)
signal.siginterrupt(signal.SIGINT, False)

need_run = False
try:
    gdb.execute("info reg", True, True)
except gdb.error, x:
    need_run = True

if need_run:
    first_cmd = "run"
else:
    first_cmd = "continue"
try:
    s = gdb.execute(first_cmd, True, True)
except gdb.error, x:
    print(lang.string("Inferior exec got "), x)
    run = False

while run:
    if s.find(" in operator new") > 0:
	is_new = True
    elif s.find(" in operator delete") > 0:
	is_new = False
    elif s.find(" exited ") > 0:
	break
    else:
	continue

    if is_new:
	gdb.execute("disable", False, False)
	gdb.execute("finish", False, False)
	gdb.execute("enable", False, False)
    addr = int(gdb.parse_and_eval("$rax"))
    line = str(gdb.execute("info line", True, True)).strip()
    if record_bt:
	bt = str(gdb.execute("backtrace", True, True)).strip()
	e = (is_new, addr, line, bt)
    else:
	e = (is_new, addr, line)
    mlist_c.acquire()
    mlist.append(e)
    mlist_c.notify()
    mlist_c.release()

    try:
	s = gdb.execute("continue", True, True)
    except gdb.error, x:
	print(lang.string("Inferior exec got "), x)
	break

mlist_c.acquire()
mlist.append("quit")
mlist_c.notify()
mlist_c.release()
p.join()
exit(0)