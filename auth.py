import tkinter as tk
from tkinter import messagebox

from auth_core.password import password_strength
from auth_core.user_service import register_user, authenticate_user
from auth_core.session import create_session
from audit import events as audit_events
from audit.logger import log_event
from database.db import init_db
from auth_core.migration import migrate_legacy_users
from auth_core import mfa_service

# SecureVault Phase 2: authentication is now backed by SQLite with
# Argon2id password hashing (see auth_core/ and database/). The legacy
# users.json plaintext-credential store is migrated automatically on
# startup by migrate_legacy_users() and is no longer read for login or
# registration -- see auth_core/migration.py for the migration strategy
# and why users.json is preserved on disk rather than deleted.
init_db()
migrate_legacy_users()

# =======================

class LoginApp:

    def __init__(
            self,
            root
    ):

        self.root = root

        self.messages = [

            "AES-256 Encryption",

            "Cross Device Restore",

            "Secure Authentication",

            "Enterprise Security"

        ]

        self.msg_index = 0

        self.show_login()

    # =======================

    def clear(self):

        for i in self.root.winfo_children():

            i.destroy()

    # =======================

    def animate_text(self):

        try:

            self.secure_text.config(

                text=self.messages[
                    self.msg_index
                ]

            )

            self.msg_index = (

                    self.msg_index + 1

            ) % len(
                self.messages
            )

            self.root.after(

                1800,

                self.animate_text

            )

        except Exception:

            pass

    # =======================

    def hero(

        self,

        parent

    ):

        left = tk.Frame(

            parent,

            bg="#081423",

            width=700

        )

        left.pack(

            side="left",

            fill="both"

        )

        left.pack_propagate(False)

        tk.Label(

            left,

            text="🛡",

            bg="#081423",

            fg="#00ffaa",

            font=(

                "Segoe UI",

                110

            )

        ).pack(
            pady=(90,25)
        )

        tk.Label(

            left,

            text="Secure File\nEncryptor",

            bg="#081423",

            fg="white",

            font=(

                "Segoe UI",

                34,

                "bold"

            )

        ).pack()

        tk.Label(

            left,

            text="Secure • Encrypt • Recover",

            bg="#081423",

            fg="#00ffaa",

            font=(

                "Segoe UI",

                15

            )

        ).pack(
            pady=20
        )

        self.secure_text = tk.Label(

            left,

            text="",

            bg="#081423",

            fg="#8c96a5",

            font=(

                "Segoe UI",

                13

            )

        )

        self.secure_text.pack()

        self.animate_text()

    # =======================

    def placeholder_entry(
            self,
            parent,
            placeholder,
            password=False
    ):

        entry = tk.Entry(

            parent,

            width=42,

            font=("Segoe UI",18),

            fg="#8b949e",

            bg="#1b2433",

            relief="flat",

            bd=0,

            insertbackground="#00ffaa"

        )

        entry.insert(
            0,
            placeholder
        )

        def focus_in(event):

            if entry.get() == placeholder:

                entry.delete(
                    0,
                    tk.END
                )

                entry.config(
                    fg="#9ca3af"
                )

                if password:

                    entry.config(
                        show="●"
                    )

        def focus_out(event):

            if entry.get().strip() == "":

                entry.config(
                    fg="#8b949e",
                    show=""
                )

                entry.insert(
                    0,
                    placeholder
                )

        entry.bind(
            "<FocusIn>",
            focus_in
        )

        entry.bind(
            "<FocusOut>",
            focus_out
        )

        return entry

    # =======================

    def show_login(self):

        self.clear()

        main = tk.Frame(

            self.root,

            bg="#06111d"

        )

        main.pack(

            fill="both",

            expand=True

        )

        self.hero(main)

        right = tk.Frame(

            main,

            bg="#06111d"

        )

        right.pack(

            side="left",

            fill="both",

            expand=True

        )

        card = tk.Frame(

            right,

            bg="#111827",

            width=700,

            height=760

        )

        card.pack(

            expand=True

        )

        card.pack_propagate(False)

        tk.Label(

            card,

            text="Welcome Back\n🔒 Session Locked",

            bg="#111827",

            fg="#00ffaa",

            font=("Segoe UI",38,"bold")

        ).pack(
            pady=(70,20)
        )

        tk.Label(

            card,

            text="Access your encrypted workspace",

            bg="#111827",

            fg="#6b7280",

            font=("Segoe UI",14)

        ).pack(
            pady=(0,50)
        )

        self.user = self.placeholder_entry(

            card,

            "Enter Username"

        )

        self.user.pack(

            pady=10,

            ipadx=80,

            ipady=18

        )

        pass_frame = tk.Frame(

            card,

            bg="#111827"

        )

        pass_frame.pack(
            pady=10
        )

        self.password = self.placeholder_entry(

            pass_frame,

            "Enter Password",

            True

        )

        self.password.pack(

            side="left",

            ipadx=55,

            ipady=18

        )

        def toggle():

            if self.password.get()=="Enter Password":

                return

            if self.password.cget("show")=="●":

                self.password.config(show="")

                eye.config(text="🙈")

            else:

                self.password.config(show="●")

                eye.config(text="👁")

        eye = tk.Button(

            pass_frame,

            text="👁",

            command=toggle,

            bg="#1b2433",

            fg="#00ffaa",

            bd=0,

            width=4,

            font=("Segoe UI",16)

        )

        eye.pack(
            side="left",
            padx=10,
            ipady=10
        )

        options = tk.Frame(

            card,

            bg="#111827"

        )

        options.pack(

            fill="x",

            padx=120,

            pady=(20,35)

        )

        remember = tk.BooleanVar()

        tk.Checkbutton(

            options,

            text="Remember Me",

            variable=remember,

            bg="#111827",

            fg="#9ca3af",

            selectcolor="#111827",

            activebackground="#111827",

            font=("Segoe UI",11)

        ).pack(
            side="left"
        )

        tk.Button(

            options,

            text="Forgot Password?",

            bg="#111827",

            fg="#00ffaa",

            bd=0,

            cursor="hand2"

        ).pack(
            side="right"
        )

        tk.Button(

            card,

            text="LOGIN →",

            command=self.login,

            bg="#00ffaa",

            fg="black",

            bd=0,

            width=24,

            height=2,

            font=(

                "Segoe UI",

                16,

                "bold"

            )

        ).pack(
            pady=(10,25)
        )

        tk.Button(

            card,

            text="+ Create Account",

            command=self.show_signup,

            bg="#111827",

            fg="#00ffaa",

            bd=0,

            font=("Segoe UI",13)

        ).pack()

        tk.Label(

            card,

            text="Protected by AES-256 Encryption",

            bg="#111827",

            fg="#65748b",

            font=("Segoe UI",10)

        ).pack(
            pady=60
        )

        self.user.bind(

            "<Return>",

            lambda e:

            self.password.focus()

        )

        self.password.bind(

            "<Return>",

            lambda e:

            self.login()

        )

    #=========================

    def show_signup(self):

        self.clear()

        main = tk.Frame(

            self.root,

            bg="#06111d"

        )

        main.pack(

            fill="both",

            expand=True

        )

        self.hero(main)

        right = tk.Frame(

            main,

            bg="#06111d"

        )

        right.pack(

            side="left",

            fill="both",

            expand=True

        )

        card = tk.Frame(

            right,

            bg="#111827",

            width=700,

            height=760

        )

        card.pack(

            expand=True

        )

        card.pack_propagate(False)

        tk.Label(

            card,

            text="Create Account",

            bg="#111827",

            fg="#00ffaa",

            font=("Segoe UI",34,"bold")

        ).pack(
            pady=(60,20)
        )

        tk.Label(

            card,

            text="Create your secure workspace",

            bg="#111827",

            fg="#6b7280",

            font=("Segoe UI",13)

        ).pack(
            pady=(0,40)
        )

        self.new_user = self.placeholder_entry(

            card,

            "Enter Username"

        )

        self.new_user.pack(

            pady=10,

            ipadx=80,

            ipady=18

        )

        self.new_pwd = self.placeholder_entry(

            card,

            "Enter Password",

            True

        )

        self.new_pwd.pack(

            pady=10,

            ipadx=80,

            ipady=18

        )

        self.confirm_pwd = self.placeholder_entry(

            card,

            "Confirm Password",

            True

        )

        self.confirm_pwd.pack(

            pady=10,

            ipadx=80,

            ipady=18

        )

        def toggle():

            state = (

                ""

                if self.new_pwd.cget("show")

                else "●"

            )

            self.new_pwd.config(

                show=state

            )

            self.confirm_pwd.config(

                show=state

            )

        tk.Button(

            card,

            text="👁 Show Password",

            command=toggle,

            bg="#1b2433",

            fg="#00ffaa",

            bd=0,

            font=("Segoe UI",12)

        ).pack(
            pady=10
        )

        self.strength = tk.Label(

            card,

            text="Password Strength",

            bg="#111827",

            fg="#7b8798",

            font=("Segoe UI",11)

        )

        self.strength.pack(
            pady=15
        )

        def update(event=None):

            self.strength.config(

                text=f"Strength: {password_strength(self.new_pwd.get())}"

            )

        self.new_pwd.bind(

            "<KeyRelease>",

            update

        )

        tk.Button(

            card,

            text="CREATE ACCOUNT",

            command=self.create_user,

            bg="#00ffaa",

            fg="black",

            width=24,

            height=2,

            bd=0,

            font=(

                "Segoe UI",

                15,

                "bold"

            )

        ).pack(
            pady=25
        )

        tk.Button(

            card,

            text="← Back To Login",

            command=self.show_login,

            bg="#111827",

            fg="#00ffaa",

            bd=0,

            font=("Segoe UI",12)

        ).pack()

    # =======================

    def signup(self):
        # Legacy quick-signup path (unused by the current UI, kept for
        # compatibility) -- now delegates to the same SQLite/Argon2id
        # registration service as create_user() instead of writing
        # plaintext credentials.

        user = self.user.get()

        pwd = self.password.get()

        if (
                not user or
                user == "Enter Username"
        ):

            messagebox.showerror(
                "Error",
                "Enter username"
            )

            return

        if (
                not pwd or
                pwd == "Enter Password"
        ):

            messagebox.showerror(
                "Error",
                "Enter password"
            )

            return

        result = register_user(user, pwd, pwd)

        if not result.success:
            messagebox.showerror("Error", result.message)
            return

        messagebox.showinfo(
            "Success",
            "Account Created"
        )
    #===========================

    def create_user(self):

        user = self.new_user.get()

        pwd = self.new_pwd.get()

        confirm = self.confirm_pwd.get()

        result = register_user(user, pwd, confirm)

        if not result.success:

            messagebox.showerror(

                "Error",

                result.message

            )

            return

        messagebox.showinfo(

            "Success",

            "Account Created"

        )

        self.show_login()

    # =======================

    def _open_authenticated_dashboard(self, username, session_id):
        """Open the protected workspace only after authentication is complete.

        If dashboard construction fails, restore the login screen instead of
        leaving the user with an empty root window.
        """
        try:
            self.clear()
            from dashboard import Dashboard
            Dashboard(root=self.root, username=username)
            self.root.securevault_session_id = session_id
            self.root.session_username = username
        except Exception as exc:
            # Never leave the application on a blank screen after a failed
            # transition. End the session we just created and restore login.
            try:
                from auth_core.session import end_session
                end_session(session_id)
            except Exception:
                pass
            import traceback
            traceback.print_exc()
            self.show_login()
            messagebox.showerror(
                "SecureVault Error",
                "The secure workspace could not be loaded. "
                "Your session was closed safely.\n\n"
                f"Technical detail: {type(exc).__name__}: {exc}"
            )

    def _show_mfa_challenge(self, username):
        """Require MFA proof before creating an authenticated session."""
        self.clear()

        main = tk.Frame(self.root, bg="#06111d")
        main.pack(fill="both", expand=True)

        card = tk.Frame(main, bg="#111827", width=680, height=560)
        card.pack(expand=True)
        card.pack_propagate(False)

        tk.Label(
            card, text="🛡", bg="#111827", fg="#00ffaa",
            font=("Segoe UI", 54)
        ).pack(pady=(45, 10))
        tk.Label(
            card, text="Multi-Factor Verification", bg="#111827",
            fg="#00ffaa", font=("Segoe UI", 28, "bold")
        ).pack()
        tk.Label(
            card,
            text="Enter the 6-digit code from your authenticator app\n"
                 "or use a one-time recovery code.",
            bg="#111827", fg="#9ca3af", font=("Segoe UI", 12),
            justify="center"
        ).pack(pady=(12, 30))

        code = tk.Entry(
            card, width=18, justify="center", font=("Consolas", 22),
            bg="#1b2433", fg="white", insertbackground="#00ffaa",
            relief="flat"
        )
        code.pack(ipady=10)
        code.focus_set()

        status = tk.Label(
            card, text="MFA is enabled for this account.", bg="#111827",
            fg="#6b7280", font=("Segoe UI", 10)
        )
        status.pack(pady=15)

        attempts = {"count": 0, "max": 5}

        def verify():
            value = code.get().strip()
            if not value:
                status.config(text="Enter your verification code.", fg="#ff4d5a")
                return

            if mfa_service.verify_login_code(username, value):
                log_event(
                    audit_events.MFA_CHALLENGE_SUCCESS,
                    username=username,
                    result="success",
                )
                session = create_session(username)
                self._open_authenticated_dashboard(username, session.id)
                return

            attempts["count"] += 1
            log_event(
                audit_events.MFA_CHALLENGE_FAILED,
                username=username,
                result="failure",
            )
            code.delete(0, tk.END)
            remaining = attempts["max"] - attempts["count"]
            if remaining <= 0:
                status.config(
                    text="Too many invalid MFA attempts. Please sign in again.",
                    fg="#ff4d5a",
                )
                verify_btn.config(state="disabled")
                back_btn.config(state="normal")
            else:
                status.config(
                    text=f"Invalid code. {remaining} attempt(s) remaining.",
                    fg="#ff4d5a",
                )

        verify_btn = tk.Button(
            card, text="VERIFY & CONTINUE →", command=verify,
            bg="#00ffaa", fg="black", bd=0, width=25, height=2,
            font=("Segoe UI", 13, "bold"), cursor="hand2"
        )
        verify_btn.pack(pady=(10, 12))

        def back_to_login():
            self.show_login()

        back_btn = tk.Button(
            card, text="← Back to Login", command=back_to_login,
            bg="#111827", fg="#00ffaa", bd=0,
            font=("Segoe UI", 11), cursor="hand2"
        )
        back_btn.pack()

        code.bind("<Return>", lambda _event: verify())

    def login(self):
        if str(self.user.cget("state")) == "disabled":
            self.user.config(state="normal")
            user = self.user.get()
            self.user.config(state="disabled")
        else:
            user = self.user.get()

        pwd = self.password.get()
        result = authenticate_user(user, pwd)

        if not result.success:
            log_event(
                audit_events.ACCOUNT_LOCKED if result.locked_out else audit_events.LOGIN_FAILURE,
                username=user,
                result="failure",
            )
            messagebox.showerror("Error", result.message)
            return

        username = result.username

        # Password verification is complete, but MFA-enabled accounts are
        # NOT authenticated yet. Do not create a session until the second
        # factor succeeds.
        if result.mfa_required:
            log_event(
                audit_events.LOGIN_PASSWORD_VERIFIED,
                username=username,
                result="mfa_pending",
            )
            self._show_mfa_challenge(username)
            return

        log_event(audit_events.LOGIN_SUCCESS, username=username, result="success")
        session = create_session(username)
        self._open_authenticated_dashboard(username, session.id)


if __name__ == "__main__":

    root = tk.Tk()

    root.title(
        "SecureVault"
    )

    root.geometry(
        "1500x900"
    )

    root.configure(
        bg="#06111d"
    )

    LoginApp(
        root
    )

    root.mainloop()