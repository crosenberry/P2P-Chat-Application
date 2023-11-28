import customtkinter as ctk
import tkinter as tk
from tkinter import scrolledtext, simpledialog, ttk

class ChatGUI:
    def __init__(self):
        self.root = ctk.CTk()  # Use CTk window
        self.root.title("P2P Chat Client")

        # Set theme to Dark
        ctk.set_appearance_mode("Dark")

        # Set the window size and make it not resizable for consistent styling
        self.root.geometry("800x600")
        self.root.resizable(False, False)

        # Initial placeholder for the username
        self.client_name = "Client_1"

        # Change Username Button with consistent CustomTkinter styling
        self.change_username_button = ctk.CTkButton(self.root, text="Change Username", command=self.change_username,
                                                    corner_radius=10)
        self.change_username_button.grid(row=0, column=0, padx=20, pady=10, sticky="w")

        # Username Label with CustomTkinter styling
        self.username_label = ctk.CTkLabel(self.root, text=f"Username: {self.client_name}", corner_radius=10)
        self.username_label.grid(row=0, column=1, padx=20, pady=10, sticky="w")

        # Chat Log with dark background and scrollbar
        self.chat_log = scrolledtext.ScrolledText(self.root, bg="#2e2e2e", fg="#eaeaea", insertbackground="white",
                                                  state='disabled', borderwidth=0, highlightthickness=0)
        self.chat_log.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")

        # Message Entry with CustomTkinter styling
        self.msg_entry = ctk.CTkEntry(self.root, corner_radius=10)
        self.msg_entry.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        # Send Button with CustomTkinter styling
        self.send_button = ctk.CTkButton(self.root, text="Send", command=self.send_msg, corner_radius=10)
        self.send_button.grid(row=2, column=1, padx=20, pady=10)

        self.send_function = None

        # Grid configuration for resizing behavior
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def set_send_function(self, send_function):
        self.send_function = send_function

    def change_username(self):
        new_username = simpledialog.askstring("Change Username", "Enter new username:", parent=self.root)
        if new_username:
            self.client_name = new_username
            self.username_label.configure(text=f"Username: {new_username}")
            change_message = f"USERNAME_CHANGE:{new_username}"
            self.send_function(change_message)

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