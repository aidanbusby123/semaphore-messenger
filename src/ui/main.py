import tkinter as tk
import socket
import time
import atexit
from hashlib import sha256

MAGIC = "69 69"

socket_path = "/tmp/carbide-client.sock"

destkey = "0"
port = "6969"

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(socket_path)

@atexit.register
def exit():
    client.close()

def connect(connect_entry):
    addr = connect_entry
    addr_len = len(addr)
    type_data = 3
    message = (bytearray.fromhex(MAGIC).decode()).encode() + int(type_data).to_bytes(1, 'little') + str(addr).encode() + "\0".encode() + (bytearray.fromhex(MAGIC).decode()).encode() + "\0".encode()
    client.sendall(message)

def send_message(event=None):
    message_content = message_entry.get()
    message_len = len(message_content)
    type_data = 1
    message = (bytearray.fromhex(MAGIC).decode()).encode() + int(type_data).to_bytes(1, 'little') + (sha256(destkey.encode())).digest() + int(time.time()).to_bytes(4, 'little') + message_len.to_bytes(4, 'little') + (message_content).encode() + (bytearray.fromhex(MAGIC).decode()).encode() + "\0".encode()
    client.sendall(message)
    message_entry.delete(0, tk.END)


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


window = tk.Tk()

window.title("Carbide Messenger")
window.geometry("800x600+0+0")

window.option_add('*tearOff', tk.FALSE)

menubar = tk.Menu(window)
window['menu'] = menubar

options_menu = tk.Menu(menubar)
menubar.add_cascade(menu=options_menu, label='Options')

options_menu.add_command(label='Connect', command=connect_window)

window.rowconfigure(0, weight=1)
window.columnconfigure(0, weight=1, minsize=150)
menu_frame = tk.Frame(master=window, height=600, width=150, relief=tk.GROOVE, borderwidth=1)
menu_frame.grid(row=0, column=0, sticky="nsew")

window.columnconfigure(1, weight=2)
message_frame = tk.Frame(master=window, height=600, width=650, relief=tk.SUNKEN, borderwidth=1)
message_frame.grid(row=1, column=1, sticky="nsew")

message_entry = tk.Entry(message_frame, width=50)
submit_button = tk.Button(message_frame, command=send_message, text="Send", width=10)

message_entry.grid(row=1, column=1, sticky="nsew")
submit_button.grid(row=1, column=2, sticky="nsew")

message_entry.bind('<Return>', send_message) # bind enter key to send message in message_entry


window.mainloop()

