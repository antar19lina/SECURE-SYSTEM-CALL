import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, ttk
import os
import shutil
import logging
import hashlib

# Set up logging
logging.basicConfig(filename='file_management.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Secure hashed passwords
USER_CREDENTIALS = {
    "admin": hashlib.sha256("password123".encode()).hexdigest()
}

class FileManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("File Management System")
        self.master.geometry("600x400")
        
        self.username = None
        self.dark_mode = False
        self.recent_files = []

        self.setup_login()

    def setup_login(self):
        self.login_frame = tk.Frame(self.master)
        self.login_frame.pack(pady=20)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0)
        self.entry_username = tk.Entry(self.login_frame)
        self.entry_username.grid(row=0, column=1)

        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0)
        self.entry_password = tk.Entry(self.login_frame, show='*')
        self.entry_password.grid(row=1, column=1)

        tk.Button(self.login_frame, text="Login", command=self.login).grid(row=2, columnspan=2)

    def login(self):
        username = self.entry_username.get()
        password = hashlib.sha256(self.entry_password.get().encode()).hexdigest()

        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
            self.username = username
            logging.info(f"{username} logged in.")
            self.show_file_management()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def show_file_management(self):
        self.login_frame.destroy()
        self.file_frame = tk.Frame(self.master)
        self.file_frame.pack(pady=10)

        actions = [
            ("Create File", self.create_file),
            ("Delete File", self.delete_file),
            ("Open File", self.open_file),
            ("Edit File", self.edit_file),
            ("Rename File", self.rename_file),
            ("Move File", self.move_file),
            ("Copy File", self.copy_file),
            ("Search File", self.search_file),
            ("Create Folder", self.create_folder),
            ("Delete Folder", self.delete_folder),
            ("Toggle Dark Mode", self.toggle_dark_mode),
            ("Logout", self.logout)
        ]

        for text, command in actions:
            tk.Button(self.file_frame, text=text, command=command).pack(pady=2)

        # Recent Files Section
        self.recent_files_frame = tk.LabelFrame(self.file_frame, text="Recent Files")
        self.recent_files_frame.pack(pady=10, fill="both", expand=True)

        self.recent_files_listbox = tk.Listbox(self.recent_files_frame)
        self.recent_files_listbox.pack(fill="both", expand=True)

        self.recent_files_listbox.bind('<Double-Button-1>', self.open_recent_file)

        self.update_recent_files()

        # Enable drag and drop
        self.file_frame.bind("<Drop>", self.drop)

    def update_recent_files(self):
        self.recent_files_listbox.delete(0, tk.END)
        for file in self.recent_files:
            self.recent_files_listbox.insert(tk.END, file)

    def open_recent_file(self, event):
        selected_file = self.recent_files_listbox.get(self.recent_files_listbox.curselection())
        self.open_file(selected_file)

    def drop(self, event):
        files = event.data.split()
        for file in files:
            if os.path.isfile(file):
                self.recent_files.append(file)
                self.update_recent_files()
                logging.info(f"{self.username} added file via drag and drop: {file}")

    def create_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, 'w') as f:
                f.write("")
            self.recent_files.append(file_path)
            self.update_recent_files()
            logging.info(f"{self.username} created file: {file_path}")

    def delete_file(self):
        file_path = filedialog.askopenfilename()
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
            self.recent_files.remove(file_path)
            self.update_recent_files()
            logging.info(f"{self.username} deleted file: {file_path}")

    def open_file(self, file_path=None):
        if not file_path:
            file_path = filedialog.askopenfilename()
        if file_path:
            os.startfile(file_path)
            logging.info(f"{self.username} opened file: {file_path}")

    def edit_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r+') as f:
                content = f.read()
                new_content = simpledialog.askstring("Edit File", "Modify content:", initialvalue=content)
                if new_content is not None:
                    with open(file_path, 'w') as f:
                        f.write(new_content)
                    logging.info(f"{self.username} edited file: {file_path}")

    def rename_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            new_name = simpledialog.askstring("Rename File", "Enter new name:")
            if new_name: new_path = os.path.join(os.path.dirname(file_path), new_name)
            os.rename(file_path, new_path)
            logging.info(f"{self.username} renamed file from {file_path} to {new_path}")

    def create_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            new_folder_name = simpledialog.askstring("Create Folder", "Enter folder name:")
            if new_folder_name:
                new_folder_path = os.path.join(folder_path, new_folder_name)
                os.makedirs(new_folder_path, exist_ok=True)
                logging.info(f"{self.username} created folder: {new_folder_path}")

    def delete_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path and os.path.exists(folder_path):
            shutil.rmtree(folder_path)
            logging.info(f"{self.username} deleted folder: {folder_path}")

    def move_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            destination = filedialog.askdirectory()
            if destination:
                shutil.move(file_path, destination)
                logging.info(f"{self.username} moved file {file_path} to {destination}")

    def copy_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            destination = filedialog.askdirectory()
            if destination:
                shutil.copy(file_path, destination)
                logging.info(f"{self.username} copied file {file_path} to {destination}")

    def search_file(self):
        search_term = simpledialog.askstring("Search File", "Enter file name or part of it:")
        if search_term:
            found_files = [f for f in os.listdir('.') if search_term in f]
            if found_files:
                messagebox.showinfo("Search Results", "\n".join(found_files))
            else:
                messagebox.showinfo("Search Results", "No files found.")

    def toggle_dark_mode(self):
        if self.dark_mode:
            self.master.config(bg='white')
            for widget in self.master.winfo_children():
                widget.config(bg='white', fg='black')
            self.dark_mode = False
            logging.info(f"{self.username} disabled dark mode.")
        else:
            self.master.config(bg='black')
            for widget in self.master.winfo_children():
                widget.config(bg='black', fg='white')
            self.dark_mode = True
            logging.info(f"{self.username} enabled dark mode.")

    def logout(self):
        logging.info(f"{self.username} logged out.")
        self.username = None
        self.file_frame.destroy()
        self.setup_login()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileManagerApp(root)
    root.mainloop()