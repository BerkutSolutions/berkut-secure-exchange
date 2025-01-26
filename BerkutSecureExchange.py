import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import webbrowser
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import socket
import threading
import datetime
from PIL import Image, ImageTk
import requests
import io
import zipfile

class CertificateManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Berkut Secure Exchange")
        self.geometry("760x470")
        self.resizable(False, False)

        self.settings_path = os.path.join(os.getcwd(), "Settings", "settings.txt")
        self.ip_history_path = os.path.join(os.getcwd(), "Settings", "ip.txt")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.create_menu()
        self.ensure_settings_file()

        self.certificates = self.get_certificates()
        self.default_cert = self.load_default_certificate()
        self.default_port = self.load_default_port()
        self.encrypt_cert_combobox = ttk.Combobox(self, values=self.certificates)
        self.decrypt_cert_combobox = ttk.Combobox(self, values=self.certificates)
        self.cert_combobox = ttk.Combobox(self, values=self.certificates)
        self.send_cert_combobox = ttk.Combobox(self, values=self.certificates)

        self.create_tabs()
        self.server_thread = None
        self.server_running = False
        self.tunnel_socket = None

        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, self.default_port)

        self.center_window()

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry('{}x{}+{}+{}'.format(width, height, x, y))

    def create_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        menubar.add_command(label="Настройки", command=self.open_settings)

    def ensure_settings_file(self):
        if not os.path.exists(self.settings_path):
            os.makedirs(os.path.dirname(self.settings_path), exist_ok=True)
            with open(self.settings_path, "w") as file:
                file.write("username\n")
                file.write("\n")
                file.write("9090\n")

    def open_settings(self):
        settings_window = tk.Toplevel(self)
        settings_window.title("Настройки")
        settings_window.geometry("400x250")
        settings_window.resizable(False, False)

        ttk.Label(settings_window, text="Имя пользователя:").grid(row=0, column=0, padx=10, pady=10)
        self.username_entry = ttk.Entry(settings_window)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(settings_window, text="Выберите сертификат:").grid(row=1, column=0, padx=10, pady=10)
        self.cert_combobox = ttk.Combobox(settings_window, values=self.certificates)
        self.cert_combobox.grid(row=1, column=1, padx=10, pady=10)

        ttk.Label(settings_window, text="Порт сервера по умолчанию:").grid(row=2, column=0, padx=10, pady=10)
        self.default_port_entry = ttk.Entry(settings_window)
        self.default_port_entry.grid(row=2, column=1, padx=10, pady=10)

        if self.default_cert:
            self.cert_combobox.set(self.default_cert)
        if self.default_port:
            self.default_port_entry.insert(0, self.default_port)

        ttk.Button(settings_window, text="Сохранить", command=self.save_settings).grid(row=3, columnspan=2, pady=10)
        self.load_settings()

    def save_settings(self):
        os.makedirs(os.path.dirname(self.settings_path), exist_ok=True)
        with open(self.settings_path, "w") as file:
            file.write(f"{self.username_entry.get()}\n")
            file.write(f"{self.cert_combobox.get()}\n")
            file.write(f"{self.default_port_entry.get()}\n")
        messagebox.showinfo("Настройки", "Настройки сохранены.")
        self.default_cert = self.cert_combobox.get()
        self.default_port = self.default_port_entry.get()
        self.refresh_comboboxes()
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, self.default_port)

    def load_settings(self):
        if os.path.exists(self.settings_path):
            with open(self.settings_path, "r") as file:
                lines = file.readlines()
                if len(lines) >= 3:
                    self.username_entry.insert(0, lines[0].strip())
                    self.cert_combobox.set(lines[1].strip())
                    self.default_port_entry.delete(0, tk.END)
                    self.default_port_entry.insert(0, lines[2].strip())
                    self.port_entry.delete(0, tk.END)
                    self.port_entry.insert(0, lines[2].strip())

    def load_default_certificate(self):
        if os.path.exists(self.settings_path):
            with open(self.settings_path, "r") as file:
                lines = file.readlines()
                if len(lines) >= 2:
                    return lines[1].strip()
        return None

    def load_default_port(self):
        if os.path.exists(self.settings_path):
            with open(self.settings_path, "r") as file:
                lines = file.readlines()
                if len(lines) >= 3:
                    return lines[2].strip()
        return None

    def create_tabs(self):
        self.tab_control = ttk.Notebook(self)

        self.create_certificate_tab = ttk.Frame(self.tab_control)
        self.certificates_tab = ttk.Frame(self.tab_control)
        self.encryption_tab = ttk.Frame(self.tab_control)
        self.decryption_tab = ttk.Frame(self.tab_control)
        self.send_tab = ttk.Frame(self.tab_control)
        self.about_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.create_certificate_tab, text="Создание сертификата")
        self.tab_control.add(self.certificates_tab, text="Сертификаты")
        self.tab_control.add(self.encryption_tab, text="Шифрование")
        self.tab_control.add(self.decryption_tab, text="Дешифрование")
        self.tab_control.add(self.send_tab, text="Отправка")
        self.tab_control.add(self.about_tab, text="Об авторе")

        self.tab_control.pack(expand=1, fill="both")

        self.create_create_certificate_tab()
        self.create_certificates_tab()
        self.create_encryption_tab()
        self.create_decryption_tab()
        self.create_send_tab()
        self.create_about_tab()

        if self.default_cert:
            self.encrypt_cert_combobox.set(self.default_cert)
            self.decrypt_cert_combobox.set(self.default_cert)
            self.send_cert_combobox.set(self.default_cert)

    def create_create_certificate_tab(self):
        ttk.Label(self.create_certificate_tab, text="ФИО:").place(x=77, y=10)
        self.fullname_entry = ttk.Entry(self.create_certificate_tab)
        self.fullname_entry.place(x=120, y=10)

        ttk.Label(self.create_certificate_tab, text="Почта:").place(x=70, y=40)
        self.email_entry = ttk.Entry(self.create_certificate_tab)
        self.email_entry.place(x=120, y=40)

        ttk.Label(self.create_certificate_tab, text="Номер телефона:").place(x=10, y=70)
        self.phone_entry = ttk.Entry(self.create_certificate_tab)
        self.phone_entry.place(x=120, y=70)

        ttk.Label(self.create_certificate_tab, text="Город:").place(x=71, y=100)
        self.city_entry = ttk.Entry(self.create_certificate_tab)
        self.city_entry.place(x=120, y=100)

        ttk.Label(self.create_certificate_tab, text="Описание:").place(x=49, y=130)
        self.description_entry = ttk.Entry(self.create_certificate_tab)
        self.description_entry.place(x=120, y=130)

        ttk.Label(self.create_certificate_tab, text="Компания:").place(x=48, y=160)
        self.company_entry = ttk.Entry(self.create_certificate_tab)
        self.company_entry.place(x=120, y=160)

        ttk.Label(self.create_certificate_tab, text="Отдел:").place(x=71, y=190)
        self.department_entry = ttk.Entry(self.create_certificate_tab)
        self.department_entry.place(x=120, y=190)

        ttk.Label(self.create_certificate_tab, text="Рабочее место:").place(x=21, y=220)
        self.position_entry = ttk.Entry(self.create_certificate_tab)
        self.position_entry.place(x=120, y=220)

        ttk.Button(self.create_certificate_tab, text="Сгенерировать сертификат", command=self.generate_certificate).place(x=10, y=250)

    def generate_certificate(self):
        fullname = self.fullname_entry.get()
        email = self.email_entry.get()
        phone = self.phone_entry.get()
        city = self.city_entry.get()
        description = self.description_entry.get()
        company = self.company_entry.get()
        department = self.department_entry.get()
        position = self.position_entry.get()

        names = fullname.split()
        if len(names) < 3:
            messagebox.showerror("Ошибка", "Введите полное ФИО (Фамилия Имя Отчество)")
            return

        last_name = names[0]
        first_name_initial = names[1][0]
        middle_name_initial = names[2][0]

        base_filename = f"{last_name}{first_name_initial}{middle_name_initial}.bcert"
        cert_filename = base_filename
        counter = 1

        while os.path.exists(os.path.join("Certificates", cert_filename)):
            cert_filename = f"{last_name}{first_name_initial}{middle_name_initial}_{counter}.bcert"
            counter += 1

        cert_path = os.path.join("Certificates", cert_filename)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        cert_data = f"ФИО: {fullname}\nПочта: {email}\nНомер телефона: {phone}\nГород: {city}\nОписание: {description}\nКомпания: {company}\nОтдел: {department}\nРабочее место: {position}".encode('utf-8')
        cert_signature = key.sign(cert_data, padding.PKCS1v15(), hashes.SHA256())

        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert_data + b"\n\n" + public_key + b"\n\n" + private_key + b"\n\n" + cert_signature)

        messagebox.showinfo("Успех", f"Сертификат создан: {cert_path}")
        self.refresh_certificates()

    def encrypt_data(self, data):
        key = b'Sixteen byte key'
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        return iv + encrypted_data

    def decrypt_data(self, data):
        key = b'Sixteen byte key'
        iv = data[:16]
        encrypted_data = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_data

    def create_certificates_tab(self):
        self.cert_listbox = tk.Listbox(self.certificates_tab, width=40)
        self.cert_listbox.place(x=10, y=35, height=400)
        self.cert_listbox.bind("<<ListboxSelect>>", self.display_certificate_info)

        self.cert_info_text = tk.Text(self.certificates_tab, state="disabled", wrap="word", width=60)
        self.cert_info_text.place(x=260, y=35, height=400)

        ttk.Button(self.certificates_tab, text="Обновить", command=self.refresh_certificates).place(x=10, y=5)

        self.refresh_certificates()

    def refresh_certificates(self):
        self.cert_listbox.delete(0, tk.END)
        self.certificates = self.get_certificates()
        for cert in self.certificates:
            self.cert_listbox.insert(tk.END, cert)
        self.refresh_comboboxes()

    def refresh_comboboxes(self):
        self.encrypt_cert_combobox['values'] = self.certificates
        self.decrypt_cert_combobox['values'] = self.certificates
        self.cert_combobox['values'] = self.certificates
        self.send_cert_combobox['values'] = self.certificates

        if self.default_cert:
            self.encrypt_cert_combobox.set(self.default_cert)
            self.decrypt_cert_combobox.set(self.default_cert)
            self.send_cert_combobox.set(self.default_cert)

    def get_certificates(self):
        certs = []
        if not os.path.exists("Certificates"):
            os.makedirs("Certificates")
        for cert in os.listdir("Certificates"):
            if cert.endswith(".bcert"):
                certs.append(cert)
        return certs

    def display_certificate_info(self, event):
        try:
            selected_cert = self.cert_listbox.get(self.cert_listbox.curselection())
            cert_path = os.path.join("Certificates", selected_cert)

            with open(cert_path, "rb") as cert_file:
                cert_content = cert_file.read()

            try:
                cert_data, public_key, private_key, cert_signature = cert_content.rsplit(b"\n\n", 3)
                cert_data = cert_data.decode('utf-8')
            except ValueError:
                messagebox.showerror("Ошибка", "Неверный формат сертификата")
                return

            is_valid = self.verify_certificate(cert_data.encode('utf-8'), public_key, cert_signature)

            self.cert_info_text.config(state="normal")
            self.cert_info_text.delete(1.0, tk.END)
            self.cert_info_text.insert(tk.END, cert_data)
            self.cert_info_text.insert(tk.END, "\n\nДостоверность: ")
            if is_valid:
                self.cert_info_text.insert(tk.END, "Подтверждено", "valid")
                self.cert_info_text.tag_config("valid", foreground="green")
            else:
                self.cert_info_text.insert(tk.END, "Фальсифицировано", "invalid")
                self.cert_info_text.tag_config("invalid", foreground="red")
            self.cert_info_text.config(state="disabled")
        except tk.TclError:
            pass

    def verify_certificate(self, cert_data, public_key, cert_signature):
        public_key = load_pem_public_key(public_key, backend=default_backend())

        try:
            public_key.verify(cert_signature, cert_data, padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            return False

    def create_encryption_tab(self):
        ttk.Label(self.encryption_tab, text="Выберите сертификат:").place(x=10, y=10)
        self.encrypt_cert_combobox = ttk.Combobox(self.encryption_tab, values=self.certificates)
        self.encrypt_cert_combobox.place(x=150, y=10)

        if self.default_cert:
            self.encrypt_cert_combobox.set(self.default_cert)

        ttk.Label(self.encryption_tab, text="Выберите файлы/папки для шифрования:").place(x=10, y=40)
        self.files_to_encrypt = []
        ttk.Button(self.encryption_tab, text="Добавить файлы", command=self.add_files_to_encrypt).place(x=10, y=70)
        ttk.Button(self.encryption_tab, text="Добавить папку", command=self.add_folder_to_encrypt).place(x=115, y=70)
        ttk.Button(self.encryption_tab, text="Очистить", command=self.clear_files_to_encrypt).place(x=214, y=70)

        self.files_listbox = tk.Listbox(self.encryption_tab)
        self.files_listbox.place(x=300, y=10, width=350, height=200)

        ttk.Button(self.encryption_tab, text="Зашифровать", command=self.encrypt_files).place(x=110, y=135)

    def add_files_to_encrypt(self):
        files = filedialog.askopenfilenames()
        for file in files:
            self.files_to_encrypt.append(file)
            self.files_listbox.insert(tk.END, file)

    def add_folder_to_encrypt(self):
        folder = filedialog.askdirectory()
        for root, _, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                self.files_to_encrypt.append(file_path)
                self.files_listbox.insert(tk.END, file_path)

    def clear_files_to_encrypt(self):
        self.files_to_encrypt.clear()
        self.files_listbox.delete(0, tk.END)

    def encrypt_files(self):
        selected_cert = self.encrypt_cert_combobox.get()
        if not selected_cert:
            messagebox.showerror("Ошибка", "Выберите сертификат для шифрования")
            return

        if not self.files_to_encrypt:
            messagebox.showerror("Ошибка", "Выберите файлы для шифрования")
            return

        cert_path = os.path.join("Certificates", selected_cert)
        with open(cert_path, "rb") as cert_file:
            cert_content = cert_file.read()

        try:
            cert_data, public_key, private_key, cert_signature = cert_content.rsplit(b"\n\n", 3)
        except ValueError:
            messagebox.showerror("Ошибка", "Неверный формат сертификата")
            return

        public_key = load_pem_public_key(public_key, backend=default_backend())

        if not os.path.exists("Encrypted"):
            os.makedirs("Encrypted")

        encrypted_file_name = f"{selected_cert.split('.')[0]}-{datetime.datetime.now().strftime('%d.%m.%Y-%H.%M.%S')}.bencf"
        encrypted_file_path = os.path.join("Encrypted", encrypted_file_name)

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in self.files_to_encrypt:
                zipf.write(file_path, os.path.basename(file_path))

        sym_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(sym_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()

        padded_data = padder.update(memory_file.getvalue()) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_sym_key = public_key.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_sym_key + iv + encrypted_data)

        messagebox.showinfo("Успех", f"Файлы успешно зашифрованы в {encrypted_file_path}")

    def create_decryption_tab(self):
        ttk.Label(self.decryption_tab, text="Выберите сертификат:").place(x=10, y=10)
        self.decrypt_cert_combobox = ttk.Combobox(self.decryption_tab, values=self.certificates)
        self.decrypt_cert_combobox.place(x=150, y=10)

        if self.default_cert:
            self.decrypt_cert_combobox.set(self.default_cert)

        self.mail_files_combobox = ttk.Combobox(self.decryption_tab, values=self.get_mail_files())
        self.mail_files_combobox.place(x=10, y=70)

        self.mail_files_checkbox = ttk.Checkbutton(self.decryption_tab, text="Использовать файл из папки Mail", command=self.toggle_mail_files)
        self.mail_files_checkbox.place(x=10, y=40)
        self.mail_files_active = tk.BooleanVar()
        self.mail_files_checkbox.config(variable=self.mail_files_active)

        ttk.Button(self.decryption_tab, text="Обновить", command=self.refresh_mail_files).place(x=300, y=70)

        ttk.Label(self.decryption_tab, text="Выберите файлы для дешифрования:").place(x=10, y=100)
        self.files_to_decrypt = []
        ttk.Button(self.decryption_tab, text="Добавить файлы", command=self.add_files_to_decrypt).place(x=10, y=120)
        ttk.Button(self.decryption_tab, text="Очистить файлы", command=self.clear_files_to_decrypt).place(x=160, y=68)

        self.decrypt_files_listbox = tk.Listbox(self.decryption_tab)
        self.decrypt_files_listbox.place(x=300, y=10, width=350, height=200)

        ttk.Button(self.decryption_tab, text="Расшифровать", command=self.decrypt_files).place(x=105, y=160)

    def refresh_mail_files(self):
        self.mail_files_combobox['values'] = self.get_mail_files()

    def toggle_mail_files(self):
        if self.mail_files_active.get():
            self.clear_files_to_decrypt()
            mail_files = self.get_mail_files()
            selected_file = self.mail_files_combobox.get()
            if selected_file:
                self.files_to_decrypt.append(selected_file)
                self.decrypt_files_listbox.insert(tk.END, selected_file)
        else:
            self.clear_files_to_decrypt()

    def get_mail_files(self):
        mail_files = []
        if not os.path.exists("Mail"):
            os.makedirs("Mail")
        for file in os.listdir("Mail"):
            if file.endswith(".bencf"):
                mail_files.append(os.path.join("Mail", file))
        return mail_files

    def add_files_to_decrypt(self):
        files = filedialog.askopenfilenames(filetypes=[("Encrypted files", "*.bencf")])
        for file in files:
            self.files_to_decrypt.append(file)
            self.decrypt_files_listbox.insert(tk.END, file)

    def clear_files_to_decrypt(self):
        self.files_to_decrypt.clear()
        self.decrypt_files_listbox.delete(0, tk.END)

    def decrypt_files(self):
        selected_cert = self.decrypt_cert_combobox.get()
        if not selected_cert:
            messagebox.showerror("Ошибка", "Выберите сертификат для дешифрования")
            return

        if not self.files_to_decrypt:
            messagebox.showerror("Ошибка", "Выберите файлы для дешифрования")
            return

        cert_key_path = os.path.join("Certificates", selected_cert)
        with open(cert_key_path, "rb") as cert_file:
            cert_content = cert_file.read()

        try:
            cert_data, public_key, private_key, cert_signature = cert_content.rsplit(b"\n\n", 3)
        except ValueError:
            messagebox.showerror("Ошибка", "Неверный формат сертификата")
            return

        private_key = load_pem_private_key(private_key, password=None, backend=default_backend())

        if not os.path.exists("Decrypted"):
            os.makedirs("Decrypted")

        for file_path in self.files_to_decrypt:
            with open(file_path, "rb") as file:
                encrypted_data = file.read()

            encrypted_sym_key = encrypted_data[:256]
            iv = encrypted_data[256:272]
            encrypted_content = encrypted_data[272:]

            try:
                sym_key = private_key.decrypt(
                    encrypted_sym_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                cipher = Cipher(algorithms.AES(sym_key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(encrypted_content) + decryptor.finalize()

                unpadder = sym_padding.PKCS7(128).unpadder()
                decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

                decrypted_folder_name = os.path.splitext(os.path.basename(file_path))[0]
                decrypted_folder_path = os.path.join("Decrypted", decrypted_folder_name)
                os.makedirs(decrypted_folder_path, exist_ok=True)

                memory_file = io.BytesIO(decrypted_data)
                with zipfile.ZipFile(memory_file, 'r') as zipf:
                    zipf.extractall(decrypted_folder_path)

                messagebox.showinfo("Успех", f"Файлы успешно расшифрованы в папку {decrypted_folder_path}")

            except ValueError:
                messagebox.showerror("Ошибка", "Дешифрование не удалось. Проверьте правильность выбранного сертификата.")

    def create_send_tab(self):
        ttk.Label(self.send_tab, text="IP адрес получателя:").place(x=480, y=10)
        self.recipient_ip_combobox = ttk.Combobox(self.send_tab)
        self.recipient_ip_combobox.place(x=600, y=10)

        ttk.Label(self.send_tab, text="Порт сервера:").place(x=480, y=40)
        self.port_entry = ttk.Entry(self.send_tab)
        self.port_entry.place(x=600, y=40)

        ttk.Button(self.send_tab, text="Подключение", command=self.connect_tunnel).place(x=480, y=70)
        ttk.Button(self.send_tab, text="Запустить сервер", command=self.start_server).place(x=640, y=70)
        ttk.Button(self.send_tab, text="Остановить сервер", command=self.stop_server).place(x=640, y=100)

        ttk.Label(self.send_tab, text="Выберите файл для отправки:").place(x=10, y=220)
        self.file_to_send_entry = ttk.Entry(self.send_tab)
        self.file_to_send_entry.place(x=180, y=220)
        ttk.Button(self.send_tab, text="Выбрать файл", command=self.select_file_to_send).place(x=310, y=218)

        ttk.Label(self.send_tab, text="Выберите сертификат для отправки:").place(x=10, y=250)
        self.send_cert_combobox = ttk.Combobox(self.send_tab, values=self.certificates)
        self.send_cert_combobox.place(x=220, y=250)

        ttk.Button(self.send_tab, text="Отправить файл", command=self.send_file).place(x=480, y=180)
        ttk.Button(self.send_tab, text="Отправить сертификат", command=self.send_certificate).place(x=590, y=180)
        ttk.Button(self.send_tab, text="Закрыть туннель", command=self.close_tunnel).place(x=480, y=100)

        self.console_text = tk.Text(self.send_tab, state="disabled", height=10, width=60)
        self.console_text.place(x=10, y=10, height=200, width=460)

        self.load_ip_history()

    def load_ip_history(self):
        if os.path.exists(self.ip_history_path):
            with open(self.ip_history_path, "r") as file:
                ips = file.read().splitlines()
                self.recipient_ip_combobox['values'] = ips

    def save_ip_history(self, ip):
        if os.path.exists(self.ip_history_path):
            with open(self.ip_history_path, "r") as file:
                ips = file.read().splitlines()
        else:
            ips = []

        if ip not in ips:
            ips.append(ip)
            with open(self.ip_history_path, "w") as file:
                file.write("\n".join(ips))

    def update_console(self, message):
        self.console_text.config(state="normal")
        self.console_text.insert(tk.END, message + "\n")
        self.console_text.config(state="disabled")

    def start_server(self):
        if not self.server_running:
            self.server_thread = threading.Thread(target=self.server_program)
            self.server_thread.start()
            self.server_running = True
            self.update_console("Сервер запущен")

    def stop_server(self):
        if self.server_running:
            self.server_running = False
            if self.server_thread:
                self.server_thread.join()
            self.update_console("Сервер остановлен")

    def server_program(self):
        host = socket.gethostname()
        port = int(self.port_entry.get())

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(2)
        self.update_console(f"Сервер слушает на {host}:{port}")

        while self.server_running:
            try:
                server_socket.settimeout(1)
                conn, address = server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, address)).start()
            except socket.timeout:
                continue

    def handle_client(self, conn, address):
        try:
            self.request_connection_permission(conn, address)
        except Exception as e:
            self.update_console(f"Ошибка при обработке клиента: {str(e)}")
            conn.close()

    def request_connection_permission(self, conn, address):
        self.update_console(f"Запрос на подключение от {address[0]}:{address[1]}")
        response = messagebox.askyesno("Разрешение подключения", f"Кто-то хочет подключиться. Разрешить?")
        if response:
            try:
                conn.send("access_granted".encode())
                self.receive_data(conn)
            except Exception as e:
                self.update_console(f"Ошибка при получении данных: {str(e)}")
            finally:
                conn.close()
        else:
            conn.send("access_denied".encode())
            self.update_console("Подключение отклонено")
            conn.close()

    def receive_data(self, conn):
        try:
            while True:
                header = conn.recv(1024).decode()
                if not header:
                    break

                if header.startswith("cert:"):
                    _, cert_name = header.split(":")
                    cert_filename = os.path.join("Certificates", cert_name)
                    cert_data = b""
                    while True:
                        data = conn.recv(4096)
                        if b"<END_CERT>" in data:
                            cert_data += data.split(b"<END_CERT>")[0]
                            break
                        cert_data += data
                    with open(cert_filename, "wb") as f:
                        f.write(cert_data)
                    self.update_console(f"Сертификат получен: {cert_filename}")
                    conn.send("Сертификат получен".encode())

                elif header.startswith("key:"):
                    _, key_name = header.split(":")
                    key_filename = os.path.join("Certificates", key_name)
                    key_data = b""
                    while True:
                        data = conn.recv(4096)
                        if b"<END_KEY>" in data:
                            key_data += data.split(b"<END_KEY>")[0]
                            break
                        key_data += data
                    with open(key_filename, "wb") as f:
                        f.write(key_data)
                    self.update_console(f"Ключ получен: {key_filename}")
                    conn.send("Ключ получен".encode())

                elif header.startswith("file:"):
                    _, file_info = header.split(":")
                    filename, filesize = file_info.split("<SEPARATOR>")
                    filename = os.path.basename(filename)
                    filesize = int(filesize)
                    file_path = os.path.join("Mail", filename)
                    with open(file_path, "wb") as f:
                        while filesize > 0:
                            bytes_read = conn.recv(min(filesize, 4096))
                            if not bytes_read:
                                break
                            f.write(bytes_read)
                            filesize -= len(bytes_read)
                    self.update_console(f"Файл получен: {filename}")
                    conn.send("Файл получен".encode())
        except Exception as e:
            self.update_console(f"Удаленный хост {conn.getpeername()[0]} разорвал соединение.")
            conn.close()

    def connect_tunnel(self):
        recipient_ip = self.recipient_ip_combobox.get()
        port = self.port_entry.get()
        if not port:
            messagebox.showerror("Ошибка", "Пожалуйста, зайдите в настройки и укажите порт.")
            return
        try:
            self.tunnel_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tunnel_socket.connect((recipient_ip, int(port)))
            self.update_console("Запрос на подключение отправлен")
            messagebox.showinfo("Информация", "Запрос на подключение отправлен")
            self.tunnel_socket.sendall("connect_request".encode())

            response = self.tunnel_socket.recv(1024).decode()
            if response == "access_granted":
                messagebox.showinfo("Успех", "Доступ разрешен")
                self.update_console("Доступ разрешен")
                self.save_ip_history(recipient_ip)
            elif response == "access_denied":
                messagebox.showwarning("Отказ", "Доступ запрещен")
                self.update_console("Доступ запрещен")
                self.tunnel_socket.close()
                self.tunnel_socket = None
        except Exception as e:
            self.update_console(f"Не удалось создать туннель: {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось создать туннель: {str(e)}")

    def select_file_to_send(self):
        file = filedialog.askopenfilename()
        self.file_to_send_entry.delete(0, tk.END)
        self.file_to_send_entry.insert(0, file)

    def send_file(self):
        file_path = self.file_to_send_entry.get()
        if not file_path:
            self.update_console("Выберите файл для отправки")
            messagebox.showwarning("Ошибка", "Выберите файл для отправки")
            return

        if not self.tunnel_socket:
            self.update_console("Нет установленного соединения для передачи данных")
            messagebox.showwarning("Ошибка", "Нет установленного соединения для передачи данных")
            return

        try:
            file_size = os.path.getsize(file_path)
            self.tunnel_socket.sendall(f"file:{os.path.basename(file_path)}<SEPARATOR>{file_size}".encode())
            with open(file_path, "rb") as file:
                while True:
                    bytes_read = file.read(4096)
                    if not bytes_read:
                        break
                    self.tunnel_socket.sendall(bytes_read)
            self.update_console("Файл успешно отправлен")
            messagebox.showinfo("Успех", "Файл успешно отправлен")
        except Exception as e:
            self.update_console(f"Не удалось отправить файл: {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось отправить файл: {str(e)}")

    def send_certificate(self):
        selected_cert = self.send_cert_combobox.get()
        if not selected_cert:
            self.update_console("Выберите сертификат для отправки")
            messagebox.showwarning("Ошибка", "Выберите сертификат для отправки")
            return

        if not self.tunnel_socket:
            self.update_console("Нет установленного соединения для передачи данных")
            messagebox.showwarning("Ошибка", "Нет установленного соединения для передачи данных")
            return

        cert_path = os.path.join("Certificates", selected_cert)
        try:
            with open(cert_path, "rb") as cert_file:
                cert_data = cert_file.read()
                self.tunnel_socket.sendall(f"cert:{selected_cert}".encode())
                self.tunnel_socket.sendall(cert_data + b"<END_CERT>")

            self.update_console("Сертификат и ключ успешно отправлены")
            messagebox.showinfo("Успех", "Сертификат и ключ успешно отправлены")
        except Exception as e:
            self.update_console(f"Не удалось отправить сертификат и ключ: {str(e)}")
            messagebox.showerror("Ошибка", f"Не удалось отправить сертификат и ключ: {str(e)}")

    def close_tunnel(self, show_message=True):
        try:
            if self.tunnel_socket:
                self.tunnel_socket.close()
                self.tunnel_socket = None
                self.update_console("Туннель закрыт")
                if show_message:
                    messagebox.showinfo("Успех", "Туннель закрыт")
            else:
                self.update_console("Нет активного туннеля для закрытия")
                if show_message:
                    messagebox.showinfo("Информация", "Нет активного туннеля для закрытия")
        except Exception as e:
            self.update_console(f"Не удалось закрыть туннель: {str(e)}")
            if show_message:
                messagebox.showerror("Ошибка", f"Не удалось закрыть туннель: {str(e)}")

    def on_closing(self):
        self.stop_server()
        self.close_tunnel(show_message=False)
        self.destroy()

    def create_about_tab(self):
        self.about_frame = ttk.Frame(self.about_tab, padding="10")
        self.about_frame.place(x=0, y=0, relwidth=1, relheight=1)

        about_text = ("Программа была разработана для безопасной передачи информации\n"
                    "при помощи шифрования самоподписанными сертификатами.\n\n"
                    "Привет, пользователь!\n"
                    "Благодарю тебя за использование моего ПО\n"
                    "Я являюсь дипломированным специалистом по защите информации\n"
                    "Если у тебя появятся какие-либо вопросы, можешь обращаться по контактам ниже\n\n"
                    "Контакты:")
        about_label = ttk.Label(self.about_frame, text=about_text, justify=tk.LEFT, anchor="n")
        about_label.place(x=0, y=0)

        telegram_link = ttk.Label(self.about_frame, text="Telegram", foreground="blue", cursor="hand2")
        telegram_link.place(x=0, y=140)
        telegram_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://t.me/berkutcommunity"))

        email_link = ttk.Label(self.about_frame, text="Почта", foreground="blue", cursor="hand2")
        email_link.place(x=70, y=140)
        email_link.bind("<Button-1>", lambda e: webbrowser.open_new("mailto:berkutosint@proton.me"))

        image_url = "https://i.postimg.cc/fR19xcKc/Kasper-Flipper512.png"
        response = requests.get(image_url)
        image_data = response.content

        image = Image.open(io.BytesIO(image_data))
        desired_width = 150
        desired_height = 150
        image = image.resize((desired_width, desired_height), Image.LANCZOS)
        render = ImageTk.PhotoImage(image)
        
        image_label = ttk.Label(self.about_frame, image=render)
        image_label.image = render
        image_label.place(x=500, y=0)

if __name__ == "__main__":
    app = CertificateManagerApp()
    app.mainloop()
