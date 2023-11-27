import tkinter as tk
from tkinter import scrolledtext
import threading

class ChatGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("P2P Chat Client")

        self.chat_log = scrolledtext.ScrolledText(self.root, state='disabled')
        self.chat_log.grid(row=0, column=0, columnspan=2)

        self.msg_entry = tk.Entry(self.root)
        self.msg_entry.grid(row=1, column=0)

        self.send_button = tk.Button(self.root, text="Send", command=self.send_msg)
        self.send_button.grid(row=1, column=1)

        self.send_function = None

    def set_send_function(self, send_function):
        self.send_function = send_function

    def send_msg(self):
        message = self.msg_entry.get()
        if message and self.send_function:
            self.send_function(message)
            self.msg_entry.delete(0, tk.END)

    def update_chat(self, message):
        self.chat_log.config(state='normal')
        self.chat_log.insert(tk.END, message + '\n')
        self.chat_log.config(state='disabled')
        self.chat_log.yview(tk.END)