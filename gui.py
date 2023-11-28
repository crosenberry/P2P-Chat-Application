import customtkinter as ctk
import tkinter as tk
from tkinter import scrolledtext, simpledialog, ttk

class ChatGUI:
    def __init__(self):
        self.root = ctk.CTk()  # Use CTk window
        self.root.title("P2P Chat Client")

        ctk.set_appearance_mode("Dark")  # Set theme to Dark

        # Configure the chat log with a dark background and light text
        self.chat_log = scrolledtext.ScrolledText(self.root, bg="#2e2e2e", fg="#eaeaea", insertbackground="white",
                                                  state='disabled')
        self.chat_log.grid(row=1, column=0, columnspan=3, sticky="nsew", padx=5, pady=5)

        self.msg_entry = ctk.CTkEntry(self.root)  # Use CTkEntry
        self.msg_entry.grid(row=2, column=0, sticky="ew", padx=5)

        self.send_button = ctk.CTkButton(self.root, text="Send", command=self.send_msg)  # Use CTkButton
        self.send_button.grid(row=2, column=1, padx=5)

        self.change_username_button = ctk.CTkButton(self.root, text="Change Username",
                                                    command=self.change_username)  # Use CTkButton
        self.change_username_button.grid(row=0, column=0, padx=5, pady=5)

        self.send_function = None

        # This is necessary for the chat log to expand and fill the space as the window resizes
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def set_send_function(self, send_function):
        self.send_function = send_function

    def _set_dropdown_values(self, client_list):
        self.client_selector['values'] = ["Broadcast to Everyone"] + client_list

    def update_client_list(self, client_list):
        self.root.after(0, lambda: self._set_dropdown_values(client_list))

    def change_username(self):
        new_username = simpledialog.askstring("Change Username", "Enter new username:", parent=self.root)
        if new_username:
            self.client_name = new_username
            change_message = f"USERNAME_CHANGE:{new_username}"
            self.send_function(change_message)
            print(f"Username changed to: {new_username}")

    def send_msg(self):
        message = self.msg_entry.get()
        if message and self.send_function:
            self.send_function(message)  # The message is expected to contain the recipient prefix
            self.msg_entry.delete(0, tk.END)

    def update_chat(self, message):
        self.chat_log.config(state='normal')
        self.chat_log.insert(tk.END, message + '\n')
        self.chat_log.config(state='disabled')
        self.chat_log.yview(tk.END)

if __name__ == "__main__":
    gui = ChatGUI()
    gui.root.mainloop()
