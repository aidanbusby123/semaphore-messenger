import socket
import time
import atexit
import os
import sys
from hashlib import sha256
import random
import base64
import datetime
import threading

TX_START = "66 26 07 01"
TX_END = "31 41 59 26"

socket_path = "semaphore-client.sock"

destkey = 0
port = "6969"

contacts = []
messages = []

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(socket_path)

@atexit.register
def exit():
    client.close()


def connect(addr):
    addr_len = len(addr)
    type_data = 5
    message = bytes.fromhex(TX_START) + int(type_data).to_bytes(1, 'little') + addr.encode() + "\0".encode() + bytes.fromhex(TX_END)
    client.sendall(message)

def send_message(message_content):
    if (len(message_content) == 0):
        return
    if destkey == 0:
        return
    type_data = 1
    message = bytes.fromhex(TX_START) + int(type_data).to_bytes(1, 'little') + destkey + int(time.time()).to_bytes(4, 'little') + len(message_content).to_bytes(4, 'little') + message_content.encode() + bytes.fromhex(TX_END)
    client.sendall(message)
    #message_entry.delete(0, tk.END)

def pubkey_exchange(key):
    type_data = 2
    message = bytes.fromhex(TX_START) + int(type_data).to_bytes(1, 'little') + bytes.fromhex(key) + int(time.time()).to_bytes(4, 'little') + bytes.fromhex(TX_END)
    client.sendall(message)


'''def add_contacts():
    def add_contacts_window_func(event=None):
        pubkey_exchange(input_entry.get())
        win.destroy()
    win = tk.Toplevel(window)
    win.geometry("400x100+0+0")
    win.columnconfigure(0, weight=1, minsize=300)
    win.columnconfigure(1, weight=2, minsize=100)
    win.minsize(400, 100)
    win.maxsize(400, 100)

    input_label = tk.Label(win, text="Contact Address", width=300)
    input_label.grid(row=0, column=0)

    input_entry = tk.Entry(win, width=300)
    input_entry.grid(row=1, column=0)

    input_entry.bind('<Return>', add_contacts_window_func)

    input_button = tk.Button(win, text="Submit", command=add_contacts_window_func)
    input_button.grid(row=1, column=1)
    win.mainloop()
'''
def get_contacts():
    contact_count = 0
    dr = os.path.join(os.path.dirname(os.getcwd()), 'pubkeys') # pubkey directory
    for path in os.listdir(dr):
        if os.path.isfile(os.path.join(dr, path)):
            contacts.append(os.path.splitext(os.path.basename(os.path.join(dr, path)))[0])
            contact_count += 1
    


def parse_stored_message(buf):
    message_tuple = [None] * 4
    if len(buf) >= 72:
        message_tuple[0] = buf[32:64]
        message_tuple[1] = buf[64:68]
        message_tuple[2] = buf[68:72]
        message_tuple[3] = buf[72:72+int.from_bytes(message_tuple[2], sys.byteorder)]
    return message_tuple

def parse_ui_message(buf):
    message_tuple = [None] * 4
    if len(buf) >= 40:
        message_tuple[0] = buf[0:32]
        message_tuple[1] = buf[32:36]
        message_tuple[2] = buf[36:40]
        content_len = int.from_bytes(message_tuple[2], 'little')
        message_tuple[3] = buf[40:40+content_len]
    return message_tuple

'''def message_window_setup(messages):
    message_list.delete(0, tk.END)
    for m in messages:
        m_buf = base64.b64decode(m)
        message_tuple = parse_stored_message(m_buf)
        print(message_tuple[3])
        message_str = '(' + str(datetime.datetime.fromtimestamp(int.from_bytes(message_tuple[1], sys.byteorder))) + ') ' + '[ ' + message_tuple[0].hex() + ' ] : ' + message_tuple[3]
        message_list.insert('end', message_str)
'''
def set_contact(destkey_str):
    global destkey
    destkey = bytearray.fromhex(destkey_str)
    dr = os.path.join(os.path.join(os.path.dirname(os.getcwd()), 'client'), 'messages')
    if os.path.isfile(os.path.join(dr, destkey_str)):
        fp = open(os.path.join(dr, destkey_str), 'rb')
        messages = fp.read().split(bytes.fromhex(TX_END))
        i = 0
        for m in messages:
            messages[i] = m.replace(bytes.fromhex(TX_START), b'')
            i += 1
      #  message_window_setup(messages)

def ui_listen():
    data = ""
    while 1:
        while 1:
            data = client.recv(2048)
            if (data.find(bytes.fromhex(TX_END)) != -1):
                data = data.replace(bytes.fromhex(TX_START), b'')
                data = data.replace(bytes.fromhex(TX_END), b'')
                m_buf = base64.b64decode(data)
                #print(m_buf)
                message_tuple = parse_ui_message(m_buf[1:])
                #print(message_tuple[3])
                message_str = '(' + str(datetime.datetime.fromtimestamp(int.from_bytes(message_tuple[1], sys.byteorder))) + ') ' + '[ ' + message_tuple[0].hex() + ' ] : ' + message_tuple[3].decode()
                print(message_str + '\n')
                break

ui_thread = threading.Thread(target=ui_listen)
ui_thread.start()
    
def main_loop():
    while 1:
        print("Message >>>")
        message_content = input()
        send_message(message_content)


get_contacts()


print("Enter server address: ")
addr = input()
connect(addr)

print("Enter contact address: ")
destkey_str = input()
set_contact(destkey_str)
if destkey in contacts:
    main_loop()
else:
    pubkey_exchange(destkey)








