import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
import platform
import subprocess

from crypto_utils import (
    decrypt_file_data,
    decrypt_file_data_with_integrity,
    password_strength
)
from audit import events as audit_events
from audit.logger import log_event


class DecryptPage:

    def __init__(self, root, back, username=None):

        self.username = username

        self.root = root
        self.back = back

        self.file = None
        self.raw_data = None
        self.decrypted_data = None
        self.original_name = None
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
            text="🔓 Restore Original File",
            bg="#071018",
            fg="#00ffaa",
            font=("Segoe UI", 30, "bold")
        ).pack(
            pady=(20, 5)
        )

        tk.Label(
            self.container,
            text="Recover your encrypted files securely",
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
            text="🔐",
            fill="#ff4d5a",
            font=("Segoe UI", 45)
        )

        self.drop_text = self.drop_area.create_text(
            325,
            130,
            text="Drag & Drop .enc file here\n- or click to browse -",
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
            text="No encrypted file selected yet",
            bg="#111827",
            fg="#9ca3af",
            font=("Segoe UI", 12, "italic")
        )

        self.file_lbl.pack(
            pady=(0, 20)
        )

        tk.Label(
            card,
            text="Decryption Password",
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
            padx=(0, 10)
        )

        self.level = tk.Label(
            pwd_frame,
            text="Strength: --",
            bg="#111827",
            fg="#9ca3af"
        )

        self.level.pack(
            side="left"
        )

        self.open_folder_var = tk.BooleanVar(
            value=True
        )

        tk.Checkbutton(
            card,
            text="Open destination folder after restoring",
            variable=self.open_folder_var,
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
            text="🔓 Restore File",
            width=22,
            height=2,
            bg="#ff4d5a",
            fg="white",
            bd=0,
            command=self.start_decryption
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

        picked = filedialog.askopenfilename(
            filetypes=[
                (
                    "Encrypted Files",
                    "*.enc"
                )
            ]
        )

        if picked:

            self.file = picked

            size = round(
                os.path.getsize(
                    self.file
                ) / 1024,
                2
            )

            self.file_lbl.config(
                text=f"Selected: {os.path.basename(self.file)} ({size} KB)",
                fg="#ff4d5a"
            )

    def check(self, event):

        self.level.config(
            text=f"Strength: {password_strength(self.password.get())}"
        )

    def start_decryption(self):

        if not self.file:

            self.file_lbl.config(
                text="⚠️ Please select .enc file first",
                fg="#ff4d5a"
            )

            return

        if not self.password.get():

            self.level.config(
                text="⚠️ Password Required",
                fg="#ff4d5a"
            )

            return

        try:

            with open(
                    self.file,
                    "rb"
            ) as f:

                raw = f.read()

            data, name, integrity_verified, is_legacy = decrypt_file_data_with_integrity(
                raw,
                self.password.get()
            )

            save = filedialog.asksaveasfilename(
                initialfile=name
            )

            if not save:
                return

            with open(
                    save,
                    "wb"
            ) as f:

                f.write(
                    data
                )

            if self.open_folder_var.get():

                try:

                    folder = os.path.dirname(
                        save
                    )

                    if platform.system() == "Windows":

                        os.startfile(
                            folder
                        )

                    elif platform.system() == "Darwin":

                        subprocess.Popen(
                            ["open", folder]
                        )

                    else:

                        subprocess.Popen(
                            ["xdg-open", folder]
                        )

                except Exception:
                    pass

            messagebox.showinfo(
                "Success",
                "File Restored Successfully!"
            )

            log_event(
                audit_events.FILE_DECRYPTED,
                username=self.username,
                result="success",
                object_id=name,
                metadata={"legacy_format": is_legacy, "integrity_verified": integrity_verified},
            )

            if not integrity_verified:
                log_event(
                    audit_events.INTEGRITY_FAILURE,
                    username=self.username,
                    result="failure",
                    object_id=name,
                    metadata={},
                )
                messagebox.showwarning(
                    "Integrity Warning",
                    "The file decrypted, but its integrity check did not match the "
                    "original. The output may not be identical to what was encrypted."
                )

            self.go_back()

        except Exception:

            log_event(
                audit_events.DECRYPTION_FAILED,
                username=self.username,
                result="failure",
                object_id=os.path.basename(self.file) if self.file else None,
                metadata={},
            )

            messagebox.showerror(
                "Error",
                "Wrong password or corrupted file"
            )

    def go_back(self):

        try:
            self.container.destroy()

        except Exception:
            pass

        self.back()