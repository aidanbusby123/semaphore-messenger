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
    message = (bytearray.fromhex(MAGIC).decode()+"\0").encode() + (str(type_data)+"\0").encode() + (addr+"\0").encode() + (port+"\0").encode() + (bytearray.fromhex(MAGIC).decode()+"\0").encode() + "\n\0".encode()
    client.sendall(message)

def send_message():
    message_content = message_entry.get()
    message_len = len(message_content)
    type_data = 1
    message = (bytearray.fromhex(MAGIC).decode()+"\0").encode() + (str(type_data)+"\0").encode() + (destkey+"\0").encode() + (str(time.time())+"\0").encode() + (str(message_len)+"\0").encode() + (message_content+"\0").encode() + (bytearray.fromhex(MAGIC).decode()+"\0").encode() + "\n\0".encode()
    client.sendall(message)
    
window = tk.Tk()

window.title("Carbide Messenger")
window.geometry("800x600+0+0")

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

