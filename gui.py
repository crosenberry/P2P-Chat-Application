import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
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

        # Dropdown for selecting the target client
        self.client_selector = ttk.Combobox(self.root, state='readonly')
        self.client_selector.grid(row=2, column=0)

        self.send_function = None

    def set_send_function(self, send_function):
        self.send_function = send_function

    def _set_dropdown_values(self, client_list):
        """Sets the values for the client selector dropdown."""
        self.client_selector['values'] = ["Broadcast to Everyone"] + client_list

    def update_client_list(self, client_list):
        """Update the dropdown with the list of connected clients, including a broadcast option."""
        self.root.after(0, lambda: self._set_dropdown_values(client_list))

    def send_msg(self):
        target_client = self.client_selector.get()
        message = self.msg_entry.get()
        if message and self.send_function:
            if target_client == "Broadcast to Everyone":
                full_message = f"Broadcast:{message}"
            else:
                full_message = f"{target_client}:{message}"
            self.send_function(full_message)
            self.msg_entry.delete(0, tk.END)

    def update_chat(self, message):
        self.chat_log.config(state='normal')
        self.chat_log.insert(tk.END, message + '\n')
        self.chat_log.config(state='disabled')
        self.chat_log.yview(tk.END)