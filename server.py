import platform
import re
import shutil
import socket
import os
import time
import traceback

commands = ['CDUP', 'CWD', 'EPRT', 'HELP', 'LIST', 'PASS', 'PORT', 'PWD', 'QUIT',
            'RETR', 'SIZE', 'STOR', 'SYST', 'TYPE', 'USER', 'RNFR', 'RNTO', 'CDUP', 'RMD', 'DELE', 'MKD']


class myFTPServer:
    def __init__(self, ip, port, buffer=1024):
        self.__ip = ip
        self.__port = port
        self.__buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = None
        self.addr = None
        self.islogin = False
        self.anonymous = False
        self.data_address = None  # for data transmission
        self.datasock = None
        self.dataVersion = None
        self.mode = 'I'  # binary as default
        self.oldname = None  # rename a file
        self.curUser = None
        self.isVIP = None

    def resetAll(self):
        self.conn = None
        self.addr = None
        self.islogin = False
        self.anonymous = False
        self.data_address = None  # for data transmission
        self.datasock = None
        self.dataVersion = None
        self.mode = 'I'  # binary as default
        self.oldname = None  # rename a file
        self.curUser = None
        self.isVIP = None

    def bind(self):
        # Wait for a client's connection.
        self.socket.bind((self.__ip, self.__port))
        self.socket.listen(1)

    def receive(self):
        # Receive data from the socket.
        return self.conn.recv(self.__buffer)

    def argCheck(self, parts):  # check whether there is an argument
        if len(parts) < 2:
            self.conn.send(b'501 Syntax error: command needs an argument.\r\n')
            return False
        else:
            return True

    def user(self, data):
        parts = data.split(" ")
        if not self.argCheck(parts): return
        username = parts[1]

        if username == "anonymous":
            self.anonymous = True
            self.conn.send(b'331 Username OK. (anonymous), send password.\r\n')
        else:
            self.curUser = username
            self.conn.send(b'331 Username OK. send password.\r\n')

    def _pass(self, data):
        parts = data.split(" ")
        if len(parts) < 2:
            self.conn.send(b'501 missing password.\r\n')
            return
        self.authenticate(parts[1])

    def authenticate(self, password):  # handle login procedure
        if self.anonymous:
            self.conn.send(b'230 Login successful.\r\n')
            self.islogin = True
            self.isVIP = True
            return
        # check user password here
        try:
            with open("users.txt", "r") as f:
                while True:
                    # Read next line
                    vip = f.readline().replace('\n', '')  # v is vip, r is regular.
                    user = f.readline().replace('\n', '')
                    passw = f.readline().replace('\n', '')
                    if not passw: break  # not empty line
                    if user == self.curUser and password == passw:
                        self.islogin = True
                        self.isVIP = True if vip == 'v' else False
                        break

            if self.islogin:
                self.conn.send(b'230 Login successful.\r\n')
            else:
                self.conn.send(b'430 Invalid username or password.\r\n')

        except Exception as e:
            print(e)
            self.conn.send(b'430 Invalid username or password.\r\n')

    def port(self, data):  # PORT 127,0,0,1,135,7
        cmd_addr = data.split(" ")
        if not self.argCheck(cmd_addr): return

        ip_port = cmd_addr[1].split(",")

        if len(ip_port) < 6:
            self.conn.send(b'504 Command not implemented for that parameter.\r\n')
            return
        ip = ".".join(str(x) for x in ip_port[0:4])  # first 4 numbers

        # check here for validity
        port = ip_port[-2:]  # the last two number
        port = int(port[0]) * 256 + int(port[1])  # conversion to decimal

        server.data_address = (ip, port)
        if not self.open_datasock():  # bind to data transmission port
            return  # connection failed.

        server.conn.send(b'200 Active data connection established.\r\n')

    def eprt(self, data):  # EPRT |1|127.0.0.1|34567|
        addr = data.split(" ")
        if not self.argCheck(addr): return

        v_ip_port = addr[1].split("|")
        v_ip_port = [x for x in v_ip_port if x != '']  # remove ''
        if len(v_ip_port) < 3:  # missing argument
            server.conn.send(b'504 Command not implemented for that parameter.\r\n')
            return

        self.dataVersion = v_ip_port[0]  # 1 is IPV4, 2 is IPV6
        ip = v_ip_port[1]
        port = int(v_ip_port[2])  # cast to int!!

        server.data_address = (ip, port)  # bind to data transmission port
        if not self.open_datasock(): return
        server.conn.send(b'200 Active data connection established.\r\n')

    def pwd(self):  # pwd
        # Print working directory of the server.
        path = os.getcwd()
        self.conn.send(f'257 \"{path}\" is the current directory.\r\n'.encode())
        print("Successfully sent server directory \n")

    def list_files(self):  # LIST (ls)
        if self.data_address is None:
            self.conn.send(b'534 File transmission before connecting.\r\n')
            return

        self.conn.send(b'125 Data connection already open. Transfer starting.\r\n')
        filelist = os.listdir('.')
        for t in filelist:
            k = self.item_info(t)
            self.datasock.send(k.encode())

        self.close_datasock()
        self.conn.send(b'226 Transfer complete.\r\n')

    def item_info(self, fn):  # fn as the filename
        st = os.stat(fn)
        ftime = time.strftime(' %b %d %H:%M ', time.gmtime(st.st_mtime))
        return ftime + fn + '\r\n'

    def retrieve(self, data):  # get(RETR)
        if self.data_address is None:
            self.conn.send(b'534 File transmission before connecting.\r\n')
            return

        parts = data.split(" ")
        if not self.argCheck(parts): return

        filename = parts[1]
        if not self.filecheck(filename): return
        print('Client is downloading file: ', filename)

        readmode = 'rb' if self.mode == 'I' else 'r'  # ascii or binary
        try:
            with open(filename, readmode) as f:
                self.conn.send(b'125 Data connection already open. Transfer starting.\r\n')
                while True:
                    bytes_read = f.read(self.__buffer)
                    if not bytes_read: break
                    self.datasock.sendall(bytes_read)

                self.conn.send(b'226 Transfer complete.\r\n')
                print("File successfully sent. \n")
        except Exception as e:
            print(e)
            self.conn.send(b"550 Connection interrupted, transfer failed.\r\n")
        self.close_datasock()

    def store(self, data):
        # Receive a file from client and save it in the server.
        if not self.isVIP:
            self.conn.send(b'550 Not enough privileges.\r\n')
            return
        parts = data.split(" ")
        if not self.argCheck(parts): return

        filename = parts[1]
        print('Storing file: ', filename)
        if self.data_address is None:
            self.conn.send(b'File transmission before connecting.\r\n')
            return
        self.conn.send(b'150 Opening data connection.\r\n')

        writemode = 'wb' if self.mode == 'I' else 'w'  # ascii or binary
        try:
            with open(filename, writemode) as f:
                while True:
                    bytes_recieved = self.datasock.recv(self.__buffer)
                    if not bytes_recieved: break
                    f.write(bytes_recieved)

            self.conn.send(b'226 Transfer complete.\r\n')
            print(f'Successfully store: {filename}\n')
        except Exception as e:
            print(e)
            traceback.print_exc()
            self.conn.send(b"550 Connection interrupted, transfer failed.\r\n")

        self.close_datasock()

    def open_datasock(self):
        if self.dataVersion == '2':
            self.datasock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)  # IPV6
        else:
            self.datasock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.datasock.connect(self.data_address)
            return True
        except:
            traceback.print_exc()
            self.conn.send(b'550 Connection establishment failure.\r\n')
            self.close_datasock()
            return False

    def close_datasock(self):
        self.datasock.close()  # close data transmission.
        self.data_address = None  # reset data port
        self.dataVersion = None

    def filecheck(self, filename):
        reg = re.compile(r'[\\/:*?"<>|\r\n]+')
        illegal = reg.findall(filename)
        if illegal:
            self.conn.send(b'550 illegal filename.\r\n')
            return False

        if not os.path.isfile(filename):
            self.conn.send(b'550 No such file or directory.\r\n')
            return False
        try:
            filesize = os.path.getsize(filename)  # test accessibility
            return True
        except Exception as e:
            print(e)
            self.conn.send(f"550 can't access file: '{filename}'.\r\n".encode())
            return False

    def cwd(self, data):
        #  Change the current working directory .
        parts = data.split(" ")
        if not self.argCheck(parts): return

        pathname = parts[1]
        try:
            os.chdir(pathname)
            print("The current directory is", os.getcwd())
            self.conn.send(
                f'250 Directory successfully changed. \"{os.getcwd()}\" is the current directory.\r\n'.encode())
        except Exception as e:
            print(e)
            self.conn.send(b'550 No such file or directory.\r\n')

    def cdup(self):
        self.cwd(f'CWD {os.path.pardir}')

    def rmdir(self, data):  # remove a directory (RMD)
        parts = data.split(' ')
        if not self.argCheck(parts): return
        dirname = parts[1]
        try:
            shutil.rmtree(dirname)
            self.conn.send(b'250 Directory removed.\r\n')
        except Exception as e:
            print(e)
            self.conn.send(b'550 No such file or directory.\r\n')

    def mkdir(self, data):  # create a new directory (MKD)
        parts = data.split(' ')
        if not self.argCheck(parts): return
        newname = parts[1]
        if os.path.isdir(newname):
            self.conn.send(f'550 Directory {newname} already exists.\r\n'.encode())
            return

        try:
            os.mkdir(newname)
            self.conn.send(f'257 Directory /{newname} created.\r\n'.encode())
        except Exception as e:
            print(e)
            self.conn.send(b'550 Failed to create.\r\n')

    def delete(self, data):  # DELE filename
        parts = data.split(' ')
        if not self.argCheck(parts): return
        filename = parts[1]
        if not self.filecheck(filename): return
        # delete the file.
        try:
            os.remove(filename)
            self.conn.send(b'250 File removed.\r\n')
        except Exception as e:
            print(e)
            self.conn.send(b'550 No such file or directory.\r\n')

    def renameFrom(self, data):
        parts = data.split(' ')
        if not self.argCheck(parts): return
        oldname = parts[1]
        if not self.filecheck(oldname): return
        self.oldname = oldname
        self.conn.send(b'350 Ready for destination name.\r\n')

    def renameTo(self, data):
        parts = data.split(' ')
        if not self.argCheck(parts): return
        newname = parts[1]
        if not self.filecheck(newname): return
        if os.path.isfile(newname):
            self.conn.send(f'550 File {newname} already exists.\r\n'.encode())
            return
        # rename file.
        try:
            os.rename(self.oldname, newname)
            self.conn.send(b'250 Renaming ok.\r\n')
        except Exception as e:
            print(e)
            self.conn.send(b'550 Rename file failed.\r\n')

    def type(self, data):
        parts = data.split(" ")
        if not self.argCheck(parts): return
        if parts[1] not in ('A', 'I'):
            self.conn.send(b'504 Command not implemented for that parameter.\r\n')
            return
        self.mode = parts[1]
        msg = 'binary' if self.mode == 'I' else 'ascii'
        self.conn.send(f'200 Type set to {msg}.\r\n'.encode())

    def quit(self):
        self.conn.send(b'221 Goodbye.\r\n')
        self.conn.close()
        self.resetAll()

    def syst(self):
        msg = f'215 system Type: {os.name}, {platform.platform()}\r\n'
        self.conn.send(msg.encode())

    def help(self):
        self.conn.send(b'214-The following commands are recognized:\r\n')
        for i in range(len(commands)): self.conn.send(f'{commands[i]} \r\n'.encode())
        self.conn.send(b'214 Help command successful.\r\n')

    def size(self, data):
        parts = data.split(" ")
        if not self.argCheck(parts): return
        if self.mode == 'A':
            self.conn.send(b'550 SIZE not allowed in ASCII mode.\r\n')
            return

        filename = parts[1]
        if not self.filecheck(filename): return
        try:
            filesize = os.path.getsize(filename)
            self.conn.send(f"213 {filename} size: {filesize} bytes.\r\n".encode())
        except Exception as e:
            print(e)
            self.conn.send(f"550 can't access file {filename}.\r\n".encode())
            return


if __name__ == "__main__":
    # FTP SERVER SETUP

    IP = "0.0.0.0"
    PORT = 52305

    server = myFTPServer(IP, PORT)
    server.bind()

    while True:

        print('FTP Server is on - {}:{}\n'.format(IP, PORT))
        server.conn, server.addr = server.socket.accept()
        server.conn.send(b'220 12110517 ready.\r\n')
        print(f'Connected by {server.addr}')

        while True:
            print("Waiting instructions------------------------------- \n")

            try:
                data = server.receive()
            except:
                traceback.print_exc()
                break

            if not data: break
            data = data.decode()
            print(f"Received command: {data}\n")
            if '\r\n' not in data:
                server.conn.send(b'linefeed error.\r\n')
                continue
            data_arr = data.split('\r\n')[:-1]  # get all except the last one(is a  '').

            # for i in range(0, len(data_arr)):
            data = data_arr[0]
            if data == 'QUIT':
                server.quit()
                break


            # login check
            if not server.islogin and data.split(' ')[0] not in ('USER', 'PASS'):
                server.conn.send(b'530 Not logged in.\r\n')
                continue

            if data == "PWD":  # pwd
                server.pwd()
            elif data == "LIST":  # ls
                server.list_files()
            elif data == 'SYST':  # syst
                server.syst()
            elif data == 'HELP':
                server.help()
            elif "PORT" in data:
                server.port(data)
            elif "EPRT" in data:
                server.eprt(data)
            elif "SIZE" in data:  # size
                server.size(data)
            elif "CWD" in data:  # cd
                server.cwd(data)
            elif data == 'CDUP':
                server.cdup()
            elif 'RMD' in data:
                server.rmdir(data)
            elif 'MKD' in data:
                server.mkdir(data)
            elif "RNFR" in data:
                server.renameFrom(data)
            elif "RNTO" in data:
                server.renameTo(data)
            elif "DELE" in data:
                server.delete(data)
            elif "USER" in data:  # user
                server.user(data)
            elif "PASS" in data:
                server._pass(data)
            elif "TYPE" in data:  # ascii / binary
                server.type(data)
            elif "RETR" in data:  # get
                server.retrieve(data)
            elif "STOR" in data:  # put
                server.store(data)
            elif "QUIT" in data:
                server.quit()
                break
            else:
                server.conn.send(b'502 Command not implemented.\r\n')

            data = None

        print('A client quits, waiting...')
