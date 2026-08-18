import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
from crypto_utils import encrypt_file_data, password_strength
from audit import events as audit_events
from audit.logger import log_event


class EncryptPage:

    def __init__(self, root, back, username=None):

        self.root = root
        self.back = back
        self.username = username

        self.file = None
        self.raw_data = None
        self.encrypted_data = None
        self.current_password = ""

        self.container = tk.Frame(
            self.root,
            bg="#071018"
        )

        self.container.pack(
            fill="both",
            expand=True
        )

        self.build_input_ui()

    def clear_container(self):

        for w in self.container.winfo_children():
            w.destroy()

    # -----------------

    def build_input_ui(self):

        self.clear_container()

        tk.Label(
            self.container,
            text="🔒 Encrypt Files",
            bg="#071018",
            fg="#00ffaa",
            font=("Segoe UI", 30, "bold")
        ).pack(
            pady=(20, 5)
        )

        tk.Label(
            self.container,
            text="Protect your sensitive files before sharing or storing",
            bg="#071018",
            fg="#9ca3af",
            font=("Segoe UI", 14)
        ).pack(
            pady=(0, 25)
        )

        card = tk.Frame(
            self.container,
            bg="#111827",
            width=850,
            height=600
        )

        card.pack()

        card.pack_propagate(False)

        self.drop_area = tk.Canvas(
            card,
            width=650,
            height=180,
            bg="#1a2235",
            highlightthickness=0,
            cursor="hand2"
        )

        self.drop_area.pack(
            pady=30
        )

        self.rect_id = self.drop_area.create_rectangle(
            10,
            10,
            640,
            170,
            outline="#4b5563",
            width=2,
            dash=(8, 8)
        )

        self.drop_icon = self.drop_area.create_text(
            325,
            75,
            text="📄",
            fill="#00ffaa",
            font=("Segoe UI", 45)
        )

        self.drop_text = self.drop_area.create_text(
            325,
            130,
            text="Drag & Drop file here\n- or click to browse -",
            fill="#9ca3af",
            justify="center",
            font=("Segoe UI", 12)
        )

        self.drop_area.bind(
            "<Button-1>",
            self.pick
        )

        self.file_lbl = tk.Label(
            card,
            text="No file selected yet",
            bg="#111827",
            fg="#9ca3af",
            font=("Segoe UI", 12, "italic")
        )

        self.file_lbl.pack(
            pady=(0, 20)
        )

        tk.Label(
            card,
            text="Encryption Password",
            bg="#111827",
            fg="white",
            font=("Segoe UI", 12, "bold")
        ).pack(
            pady=(10, 5)
        )

        pwd_frame = tk.Frame(
            card,
            bg="#111827"
        )

        pwd_frame.pack()

        self.password = tk.Entry(
            pwd_frame,
            show="●",
            width=26,
            font=("Segoe UI", 14),
            bg="#1a2235",
            fg="white",
            insertbackground="white",
            bd=0
        )

        self.password.pack(
            side="left",
            padx=(10, 5),
            ipady=6
        )

        self.password.bind(
            "<KeyRelease>",
            self.check
        )

        self.show_btn = tk.Button(
            pwd_frame,
            text="👁️",
            bg="#1a2235",
            fg="white",
            bd=0,
            command=self.toggle_password
        )

        self.show_btn.pack(
            side="left",
            padx=(0, 10),
            ipady=4,
            ipadx=4
        )

        self.level = tk.Label(
            pwd_frame,
            text="Strength: --",
            bg="#111827",
            fg="#9ca3af",
            width=15
        )

        self.level.pack(
            side="left"
        )

        self.secure_del_var = tk.BooleanVar()

        tk.Checkbutton(
            card,
            text="Securely delete original file after encryption",
            variable=self.secure_del_var,
            bg="#111827",
            fg="#9ca3af",
            selectcolor="#1a2235"
        ).pack(
            pady=(15, 0)
        )

        btn_frame = tk.Frame(
            card,
            bg="#111827"
        )

        btn_frame.pack(
            pady=30
        )

        tk.Button(
            btn_frame,
            text="⬅ Cancel",
            width=18,
            height=2,
            bg="#374151",
            fg="white",
            bd=0,
            command=self.go_back
        ).pack(
            side="left",
            padx=15
        )

        tk.Button(
            btn_frame,
            text="🔒 Start Encryption",
            width=22,
            height=2,
            bg="#00ffaa",
            fg="black",
            bd=0,
            command=self.start_encryption
        ).pack(
            side="left",
            padx=15
        )

    def toggle_password(self):

        if self.password.cget("show") == "●":

            self.password.config(show="")

            self.show_btn.config(text="🙈")

        else:

            self.password.config(show="●")

            self.show_btn.config(text="👁️")

    def pick(self, event=None):

        picked = filedialog.askopenfilename()

        if picked:

            self.file = picked

            size = round(
                os.path.getsize(
                    self.file
                ) / 1024,
                2
            )

            filename = os.path.basename(
                self.file
            )

            self.file_lbl.config(
                text=f"Selected: {filename} ({size} KB)",
                fg="#00ffaa"
            )

    def check(self, event):

        strength = password_strength(
            self.password.get()
        )

        self.level.config(
            text=f"Strength: {strength}"
        )

    def start_encryption(self):

        if not self.file:

            self.file_lbl.config(
                text="⚠️ Please select a file first!",
                fg="#ff4d5a"
            )

            return

        if not self.password.get():

            self.level.config(
                text="⚠️ Password Required",
                fg="#ff4d5a"
            )

            return

        self.current_password = self.password.get()

        try:

            with open(
                    self.file,
                    "rb"
            ) as f:

                self.raw_data = f.read()

            self.encrypted_data = encrypt_file_data(
                self.raw_data,
                self.current_password,
                os.path.basename(
                    self.file
                )
            )

            save = filedialog.asksaveasfilename(
                defaultextension=".enc",
                initialfile=os.path.basename(self.file) + ".enc"
            )

            if not save:
                return

            with open(
                    save,
                    "wb"
            ) as f:

                f.write(
                    self.encrypted_data
                )

            deleted = False

            if self.secure_del_var.get():

                if os.path.exists(self.file):

                    try:

                        os.remove(
                            self.file
                        )

                        deleted = True

                    except Exception:

                        deleted = False

            messagebox.showinfo(
                "Success",
                "File Encrypted Successfully!"
            )

            log_event(
                audit_events.FILE_ENCRYPTED,
                username=self.username,
                result="success",
                object_id=os.path.basename(self.file),
                metadata={"size_bytes": len(self.raw_data)},
            )

            self.go_back()

        except Exception:

            messagebox.showerror(
                "Error",
                "Encryption Failed. Please try again."
            )

    def go_back(self):

        try:

            self.container.destroy()

        except Exception:

            pass

        self.back()