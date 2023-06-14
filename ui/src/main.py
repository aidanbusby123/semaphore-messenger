import tkinter as tk
import socket

socket_path = "/tmp/carbide-client.sock"

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(socket_path)

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



window.mainloop()


