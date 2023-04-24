'''
Example:
    1. Finish the server, and run it in an arbitrary directory.
    ```sh
    sudo python server.py
    ```

    2. In another directory, download any file in the folder.
    ```sh™™£
    ftp -Aa 127.0.0.1:server.py
    ```
    In this example we download the script itself.

Remember to rename it.
'''
import socket

def ftp_server():
    s = socket.socket()
    s.bind(("0.0.0.0", 2121))
    s.listen(1)

    while True:
        client, addr = s.accept()

        # Send welcome message
        client.send(b"220 Welcome to CS305 Demo - SID\r\n")

        line = client.recv(1024).decode('ascii').strip()
        while line != "QUIT":
            if line[:4] == "USER":

                # Send welcome message
                pass

            elif line[:4] == "PORT":

                # Parse the data coonection ip and port
                pass

            elif line[:4] == "EPRT":

                # Same as PORT
                pass

            elif line[:4] == "STOR":
                # data_sock = socket.socket()
                # data_sock.connect((client_ip, client_port))
                # client.send(b"125 Data connection already open. Transfer starting.\r\n")
                # filename = command[5:]
                # with open(filename, 'wb') as f:
                #     data = data_sock.recv(1024)
                # f.write(data)
                # client.send(b"226 Transfer complete.\r\n")
                # data_sock.close()
                # Establish data connection
                pass

            elif line[:4] == "RETR":

                # Same as STOR
                pass

            elif line[:4] == "SIZE":

                pass

            else:

                pass

            line = client.recv(1024).decode('ascii').strip()

        client.close()

# Listening on port 2121


if __name__ =='__main__':
    ftp_server()
