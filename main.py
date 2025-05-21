import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filepath, password):
    try:
        with open(filepath, 'rb') as file:
            original_data = file.read()

        salt = os.urandom(16)
        key = generate_key(password, salt)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(original_data)

        enc_file_path = filepath + '.enc'
        with open(enc_file_path, 'wb') as file:
            file.write(salt + encrypted_data)

        messagebox.showinfo("🔐 Success", f"File encrypted successfully!\nSaved as:\n{enc_file_path}")
    except Exception as e:
        messagebox.showerror("❌ Error", f"Encryption failed:\n{str(e)}")

def decrypt_file(filepath, password):
    try:
        with open(filepath, 'rb') as file:
            content = file.read()

        salt = content[:16]
        encrypted_data = content[16:]
        key = generate_key(password, salt)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)

        dec_file_path = filepath.replace('.enc', '.dec')
        with open(dec_file_path, 'wb') as file:
            file.write(decrypted_data)

        messagebox.showinfo("🔓 Success", f"File decrypted successfully!\nSaved as:\n{dec_file_path}")
    except Exception as e:
        messagebox.showerror("❌ Error", f"Decryption failed:\n{str(e)}")

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure File Encryption/Decryption Tool")
        self.root.geometry("540x420")
        self.root.configure(bg="#f0f4f7")
        self.root.resizable(False, False)

        self.file_path = tk.StringVar()
        self.password = tk.StringVar()

        title = tk.Label(root, text="🔒 File Encryption & Decryption Tool", font=('Segoe UI', 16, 'bold'), bg="#f0f4f7", fg="#0a3d62")
        title.pack(pady=20)

        frame = tk.Frame(root, bd=2, relief=tk.RIDGE, padx=15, pady=15, bg="white")
        frame.pack(pady=10, padx=20)

        tk.Label(frame, text="📄 Select File:", font=('Segoe UI', 12), bg="white").grid(row=0, column=0, sticky='w', pady=5)
        tk.Entry(frame, textvariable=self.file_path, width=45, font=('Segoe UI', 10), state='readonly').grid(row=1, column=0, padx=5, pady=5, columnspan=2)
        ttk.Button(frame, text="Browse", command=self.browse_file).grid(row=1, column=2, padx=10)

        tk.Label(frame, text="🔑 Enter Password:", font=('Segoe UI', 12), bg="white").grid(row=2, column=0, sticky='w', pady=10)
        tk.Entry(frame, textvariable=self.password, show="*", width=30, font=('Segoe UI', 11)).grid(row=3, column=0, padx=5, pady=5, columnspan=3)

        ttk.Button(frame, text="🔐 Encrypt File", command=self.encrypt_action).grid(row=4, column=0, pady=20, ipadx=10)
        ttk.Button(frame, text="🔓 Decrypt File", command=self.decrypt_action).grid(row=4, column=1, pady=20, ipadx=10)

        footer = tk.Label(root, text="© Micro IT Internship Project", font=("Segoe UI", 9), bg="#f0f4f7", fg="gray")
        footer.pack(side="bottom", pady=10)

    def browse_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_path.set(filepath)

    def encrypt_action(self):
        if not self.file_path.get() or not self.password.get():
            messagebox.showwarning("⚠️ Missing Info", "Please select a file and enter a password.")
            return
        encrypt_file(self.file_path.get(), self.password.get())

    def decrypt_action(self):
        if not self.file_path.get() or not self.password.get():
            messagebox.showwarning("⚠️ Missing Info", "Please select a file and enter a password.")
            return
        decrypt_file(self.file_path.get(), self.password.get())

if __name__ == '__main__':
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
