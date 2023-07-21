import tkinter as tk
import socket
import time
import atexit
import os
from hashlib import sha256
import random

MAGIC = "69 69"

socket_path = "/tmp/carbide-client.sock"

destkey = "0"
port = "6969"

contacts = []

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(socket_path)

@atexit.register
def exit():
    client.close()

def connect():
    addr = "127.0.0.1"
    addr_len = len(addr)
    type_data = 5
    message = (bytearray.fromhex(MAGIC).decode()).encode() + int(type_data).to_bytes(1, 'little') + str(addr).encode() + "\0".encode() + (bytearray.fromhex(MAGIC).decode()).encode()
    client.sendall(message)

def send_message(event=None):
    message_content = message_entry.get()
    type_data = 1
    message = (bytearray.fromhex(MAGIC).decode()).encode() + int(type_data).to_bytes(1, 'little') + (sha256(destkey.encode())).digest() + int(time.time()).to_bytes(4, 'little') + len(message_content).to_bytes(4, 'little') + message_content.encode() + (bytearray.fromhex(MAGIC).decode()).encode()
    client.sendall(message)
    message_entry.delete(0, tk.END)

def pubkey_exchange(destkey):
    type_data = 2
    message = (bytearray.fromhex(MAGIC).decode()).encode() + int(type_data).to_bytes(1, 'little') + (sha256(destkey.encode())).digest() + int(time.time()).to_bytes(4, 'little') + (bytearray.fromhex(MAGIC).decode()).encode()
    client.sendall(message)


def connect_window():
    def connect_window_func(event=None):
        connect(input_entry.get())
        win.destroy()

    win = tk.Toplevel(window)
    win.geometry("400x100+0+0")
    win.columnconfigure(0, weight=1, minsize=300)
    win.columnconfigure(1, weight=2, minsize=100)
    win.minsize(400, 100)
    win.maxsize(400, 100)

    input_label = tk.Label(win, text="Server address", width=300)
    input_label.grid(row=0, column=0)

    input_entry = tk.Entry(win, width=300)
    input_entry.grid(row=1, column=0)

    input_entry.bind('<Return>', connect_window_func)

    input_button = tk.Button(win, text="Submit", command=connect_window_func)
    input_button.grid(row=1, column=1)
    win.mainloop()

def add_contacts():
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

def get_contacts():
    contact_count = 0
    dr = os.path.join(os.path.join(os.path.dirname(os.getcwd()), 'client'), 'pubkeys')
    for path in os.listdir(dr):
        if os.path.isfile(os.path.join(dr, path)):
            contacts.append(os.path.splitext(os.path.basename(os.path.join(dr, path)))[0])
            contact_count += 1
    

def contact_window_setup(contacts):
    for i in contacts:
        contact_list.insert('end', i)

def set_contact(event=None):
    destkey = bytearray.fromhex(contacts[int((contact_list.curselection())[0])])
    print(int((contact_list.curselection())[0]))

# Tkinter UI 

window = tk.Tk()

window.title("Carbide Messenger")
window.geometry("800x600+0+0")

window.option_add('*tearOff', tk.FALSE)

menubar = tk.Menu(window)
window['menu'] = menubar

options_menu = tk.Menu(menubar)
menubar.add_cascade(menu=options_menu, label='Options')

options_menu.add_command(label='Connect', command=connect)
options_menu.add_command(label='New Contact', command=add_contacts)

window.rowconfigure(0, weight=1)
window.columnconfigure(0, weight=1, minsize=150)
window.columnconfigure(1, weight=2, minsize=30)
contact_frame = tk.Frame(master=window, height=600, width=150, relief=tk.GROOVE, borderwidth=1)
contact_frame.grid(row=0, column=0, sticky="nsew")

contact_list = tk.Listbox(contact_frame)
contact_scroll = tk.Scrollbar(contact_frame, orient=tk.VERTICAL, command=contact_list.yview)
contact_list['yscrollcommand'] = contact_scroll.set

contact_list.pack(side='left', fill='both', expand=True)
contact_scroll.pack(side='right', fill='both')

contact_list.bind('<<ListboxSelect>>', set_contact)

window.columnconfigure(1, weight=2)
message_frame = tk.Frame(master=window, height=600, width=650, relief=tk.SUNKEN, borderwidth=1)
message_frame.grid(row=1, column=1, sticky="nsew")

message_entry = tk.Entry(message_frame, width=50)
submit_button = tk.Button(message_frame, command=send_message, text="Send", width=10)

message_entry.grid(row=1, column=1, sticky="nsew")
submit_button.grid(row=1, column=2, sticky="nsew")

message_entry.bind('<Return>', send_message) # bind enter key to send message in message_entry

get_contacts()
contact_window_setup(contacts)

window.mainloop()

