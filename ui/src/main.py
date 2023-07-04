import tkinter as tk
import socket
import time
import atexit

MAGIC = "0310"

socket_path = "/tmp/carbide-client.sock"

destkey = "0"
port = "6969"

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(socket_path)

@atexit.register
def exit():
    client.close()

def connect():
    addr = connect_entry.get()
    addr_len = len(addr)
    type_data = 3
    message = (bytearray.fromhex(MAGIC).decode()+"\0").encode() + (str(type_data)+"\0").encode() + (addr+"\0").encode() + (bytearray.fromhex(MAGIC).decode()+"\0").encode() + "\n\0".encode()
    client.sendall(message)

def send_message():
    message_content = message_entry.get()
    message_len = len(message_content)
    type_data = 1
    message = (bytearray.fromhex(MAGIC).decode()+"\0").encode() + (str(type_data)+"\0").encode() + (destkey+"\0").encode() + (str(int(time.time()))+"\0").encode() + (str(message_len)+"\0").encode() + (message_content+"\0").encode() + (bytearray.fromhex(MAGIC).decode()+"\0").encode() + "\n\0".encode()
    client.sendall(message)

def connect_window():
    win = tk.Toplevel(window)

    input_label = tk.Label(win, text="Server address")
    input_label.grid(row=0, column=0)

    input_entry = tk.Entry(win, width=100)
    input_entry.grid(row=1, column=0)

    input_button = tk.Button(win, text="Submit", command=lambda: [win.destroy(), connect()])
    input_button.grid(row=1, column = 1)

    
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

window.columnconfigure(1, weight=2, minsize=650)
message_frame = tk.Frame(master=window, height=600, width=650, relief=tk.SUNKEN, borderwidth=1)
message_frame.grid(row=0, column=1, sticky="nsew")

message_entry = tk.Entry(message_frame, width=100)
connect_entry = tk.Entry(menu_frame, width=100)

connect_button = tk.Button(menu_frame, command=connect)
submit_button = tk.Button(message_frame, command=send_message)

message_entry.grid(row=0, column=1, sticky="nsew")
connect_entry.grid(row=0, column=0, sticky="nsew")
connect_button.grid(row=1, column=0, sticky="nsew")
submit_button.grid(row=1, column=1, sticky="nsew")


window.mainloop()

