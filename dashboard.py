# ==========================
# dashboard.py (PART 1/3)
# ==========================

import tkinter as tk
import time
from tkinter import simpledialog
from tkinter import filedialog, messagebox
from tkinter import *
from PIL import Image, ImageTk
import json
import os
from datetime import datetime

from encrypt import EncryptPage
from decrypt import DecryptPage
from auth import LoginApp
from auth_core.password import hash_password
from database import user_repository as user_repo
from auth_core import session as session_service
from audit import events as audit_events
from audit.logger import log_event, search_events
from audit.verifier import verify_audit_log
from core.security_center import build_report as build_security_report
from core.health_check import run_health_check, PASS as HC_PASS, WARNING as HC_WARNING, FAIL as HC_FAIL
from core.alerts import run_alerts
from core.scanner import analyze_file
from services import quarantine_service as quarantine_svc
from services import report_service
from auth_core import mfa as totp
from auth_core import mfa_service


STATS = "stats.json"

PROFILE = "profiles.json"

SETTINGS = "settings.json"

class Dashboard:

    def C(self,key):

        themes={

        "dark":{

        "bg":"#081423",

        "card":"#111827",

        "text":"white",

        "row":"#182131"

        },

        "light":{

        "bg":"#f3f4f6",

        "card":"white",

        "text":"black",

        "row":"#e5e7eb"

        },

        "cyber":{

        "bg":"#05060a",

        "card":"#111111",

        "text":"#00ffaa",

        "row":"#14181d"

        },

        "ocean":{

        "bg":"#08111f",

        "card":"#132238",

        "text":"white",

        "row":"#1c3550"

        }

        }


        return themes[

            self.theme

        ][key]

    def __init__(self, root, username):

        self.root = root
        self.user = username
        self.root.title("SecureVault — Security Workspace")
        self.root.minsize(1180, 760)
        self.last_activity=time.time()
        self._page_after_ids = []
        self._monitor_job = None
        self._session_timer_job = None
        self._destroyed = False

        self.lock_minutes=5

        self.root.bind_all(

        "<Motion>",

        self.reset_activity

        )

        self.root.bind_all(

        "<Key>",

        self.reset_activity

        )

        self.monitor_activity()

        self.profile_data = self.load_profile()
        self.theme = self.load_theme()

        self.COLORS = {}

        self.apply_theme()

        self.root.configure(
            bg=self.COLORS["bg"]
        )

        self.sidebar = None
        self.main = None

        self.build()

        if hasattr(

            self.root,

            "session_start"

        ):

            self.session_start = (

                self.root.session_start

            )

        else:

            self.session_start = (

                time.time()

            )

        self.root.after(

            1000,

            self.update_session_timer

        )
        self.dashboard()
        if not hasattr(

        self.root,

        "already_logged"

        ):

            self.log_activity(

            "🟢 Logged In"

            )

            self.root.already_logged=True
        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.app_close
        )
    # ==================

    def page_after(self, delay, callback):
        """Schedule a callback tied to the current page and cancel it on navigation."""
        job = self.root.after(delay, callback)
        self._page_after_ids.append(job)
        return job

    def clear(self):

        for job in self._page_after_ids:
            try:
                self.root.after_cancel(job)
            except Exception:
                pass
        self._page_after_ids.clear()

        for w in self.main.winfo_children():
            w.destroy()

        self.page = Frame(
            self.main,
            bg=self.COLORS["bg"]
        )

        self.page.pack(
            fill="both",
            expand=True
        )

        self.canvas = Canvas(
            self.page,
            bg=self.COLORS["bg"],
            highlightthickness=0
        )

        self.scroll = Scrollbar(
            self.page,
            orient="vertical",
            command=self.canvas.yview
        )

        self.canvas.configure(
            yscrollcommand=self.scroll.set
        )

        self.scroll.pack(
            side="right",
            fill="y"
        )

        self.canvas.pack(
            side="left",
            fill="both",
            expand=True
        )

        self.content = Frame(
            self.canvas,
            bg=self.COLORS["bg"]
        )

        self.canvas_window = self.canvas.create_window(
            (0, 0),
            window=self.content,
            anchor="nw"
        )

        def update(event=None):

            self.canvas.configure(
                scrollregion=
                self.canvas.bbox("all")
            )

        self.content.bind(
            "<Configure>",
            update
        )

        def resize(event):

            self.canvas.itemconfig(
                self.canvas_window,
                width=event.width
            )

        self.canvas.bind(
            "<Configure>",
            resize
        )

        def wheel(event):

            self.canvas.yview_scroll(
                int(-event.delta/120),
                "units"
            )

        self.canvas.bind_all(
            "<MouseWheel>",
            wheel
        )
    # ==================

    def build(self):

        # LEFT SIDEBAR
        self.sidebar = Frame(
            self.root,
            bg=self.COLORS["panel"],
            width=280
        )

        self.sidebar.pack(
            side=LEFT,
            fill=Y
        )

        self.sidebar.pack_propagate(False)

        # RIGHT MAIN AREA
        self.main = Frame(
            self.root,
            bg=self.COLORS["bg"]
        )

        self.main.pack(
            side=LEFT,
            fill=BOTH,
            expand=True
        )

        self.sidebar_ui()

    # ==================

    def safe_navigate(self, fn):
        """Render a page safely so a page-level exception never leaves a blank shell."""
        try:
            session_id = getattr(self.root, "securevault_session_id", None)
            if session_id:
                session_service.require_active(session_id)
            fn()
        except Exception as exc:
            import traceback
            traceback.print_exc()
            try:
                log_event(
                    audit_events.SETTINGS_CHANGED,
                    username=self.user,
                    result="error",
                    metadata={"component": "navigation", "error": type(exc).__name__},
                )
            except Exception:
                pass
            self._render_error_page(exc)

    def _render_error_page(self, exc):
        """Show a recoverable error screen instead of an empty main area."""
        try:
            self.clear()
            page = self.content
            Label(
                page,
                text="⚠ SecureVault could not load this view",
                bg=self.COLORS["bg"],
                fg=self.COLORS["danger"],
                font=("Segoe UI", 24, "bold"),
            ).pack(anchor="w", pady=(20, 10))
            Label(
                page,
                text="The protected session is still active. You can return to the dashboard or retry the view.",
                bg=self.COLORS["bg"],
                fg=self.C("text"),
                font=("Segoe UI", 12),
                wraplength=800,
                justify="left",
            ).pack(anchor="w", pady=(0, 15))
            detail = f"{type(exc).__name__}: {exc}"
            Label(
                page,
                text=detail,
                bg=self.COLORS["card"],
                fg=self.C("muted"),
                font=("Consolas", 10),
                wraplength=800,
                justify="left",
                padx=15,
                pady=15,
            ).pack(fill=X, pady=10)
            Button(
                page,
                text="← Return to Dashboard",
                command=lambda: self.safe_navigate(self.dashboard),
                bg=self.COLORS["accent"],
                fg="black",
                bd=0,
                cursor="hand2",
                font=("Segoe UI", 12, "bold"),
                padx=18,
                pady=10,
            ).pack(anchor="w", pady=15)
        except Exception:
            # Last-resort: never allow an exception handler itself to destroy
            # the user's window. The traceback remains available in the console.
            import traceback
            traceback.print_exc()

    def nav_button(

            self,

            text,

            fn

    ):

        Button(

            self.sidebar,

            text=text,

            command=lambda f=fn: self.safe_navigate(f),

            bg=self.COLORS["panel"],

            fg=self.C("text"),

            activebackground=self.COLORS["accent"],

            activeforeground="black",

            bd=0,

            font=(

                "Segoe UI",

                12

            ),

            padx=20,

            anchor="w",
            relief="flat",
            highlightthickness=0,
            cursor="hand2"

        ).pack(

            fill=X,

            pady=3,

            padx=10

        )

    # ==================

    def sidebar_ui(self):

        Label(

            self.sidebar,

            text="🛡",

            bg=self.COLORS["panel"],

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                45

            )

        ).pack(

            pady=(35, 10)

        )

        Label(

            self.sidebar,

            text="SecureVault",

            bg=self.COLORS["panel"],

            fg=self.C("text"),

            font=(

                "Segoe UI",

                22,

                "bold"

            )

        ).pack()

        Label(

            self.sidebar,

            text="ENTERPRISE SECURITY WORKSPACE",

            bg=self.COLORS["panel"],

            fg=self.COLORS["accent"]

        ).pack(

            pady=15

        )

        items = [

            ("🏠 Dashboard", self.dashboard),

            ("🔒 Encrypt File", self.encrypt),

            ("🔓 Decrypt File", self.decrypt),

            ("🕵 File Scanner", self.file_scanner),

            ("🛡 Security Center", self.security_center),

            ("🔑 MFA & Recovery", self.mfa_setup),

            ("📜 Activity", self.activity),

            ("🧪 Quarantine", self.quarantine_page),

            ("📊 Reports", self.reports_page),

            ("📁 History",self.history),

            ("👤 Profile", self.profile),

            ("⚙ Settings", self.settings),

            ("ℹ About", self.about)

        ]

        for t, f in items:

            self.nav_button(

                t,

                f

            )

        Frame(

            self.sidebar,

            bg="#14314a",

            height=2

        ).pack(

            fill=X,

            padx=20,

            pady=12

        )

        Label(
            self.sidebar,
            text="● SESSION PROTECTED",
            bg=self.COLORS["panel"],
            fg=self.COLORS["accent"],
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w", padx=22, pady=(0, 8))

        Button(

            self.sidebar,

            text="⎋ Logout",

            command=self.logout,

            bg=self.COLORS["danger"],

            fg=self.C("text"),

            activebackground="#ff295c",

            activeforeground="white",

            bd=0,

            cursor="hand2",

            font=(

                "Segoe UI",

                13,

                "bold"

            ),

            height=2

        ).pack(

            fill=X,

            padx=20,

            pady=(10,15)

        )

    # ==================

    def top(self):

        top = Frame(
            self.content,
            bg=self.COLORS["bg"]
        )

        top.pack(
            fill=X,
            padx=40,
            pady=(20,30)
        )

        left = Frame(
            top,
            bg=self.COLORS["bg"]
        )

        left.pack(side=LEFT)

        Label(
            left,
            text=f"Welcome Back, {self.user}",
            bg=self.COLORS["bg"],
            fg=self.C("text"),
            font=("Segoe UI",34,"bold")
        ).pack(anchor="w")

        Label(
            left,
            text="Choose an operation below",
            bg=self.COLORS["bg"],
            fg=self.COLORS["muted"],
            font=("Segoe UI",14)
        ).pack(anchor="w")

        profile = Frame(
            top,
            bg=self.COLORS["card"],
            cursor="hand2"
        )

        profile.pack(
            side=RIGHT,
            padx=20
        )

        # LOCK BUTTON
        lock_btn = Button(
            top,
            text="🔒 Lock",
            command=self.lock_screen,
            bg=self.COLORS["danger"],
            fg="white",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            padx=15,
            pady=6
        )

        lock_btn.pack(
            side=RIGHT,
            padx=10
        )

        # SESSION TIMER

        timer = Frame(

            top,

            bg=self.COLORS["bg"]

        )

        timer.pack(

            side=RIGHT,

            padx=15

        )

        self.timer_label = Label(

            timer,

            text="🟢 Active • 00:00:00",

            bg=self.COLORS["bg"],

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                10,

                "bold"

            )

        )

        self.timer_label.pack()

        def goto(event=None):
            self.profile()
        
        small = self.profile_data.get(

            "photo"

        )

        try:

            img = Image.open(

                small

            )

            img = img.resize(

                (

                    70,

                    70

                )

            )

            self.small_profile = ImageTk.PhotoImage(

                img

            )

        except Exception:

            self.small_profile = None

        if self.small_profile:

            icon = Label(

                profile,

                image=self.small_profile,

                bg=self.COLORS["card"]

            )

        else:

            icon = Label(

                profile,

                text="👤",

                bg=self.COLORS["card"],

                fg=self.COLORS["accent"],

                font=(

                    "Segoe UI",

                    35

                )

            )

        icon.pack()

        name = Label(
            profile,
            text=self.user,
            bg=self.COLORS["card"],
            fg=self.C("text"),
            cursor="hand2"
        )

        name.pack()

        profile.bind("<Button-1>",goto)
        icon.bind("<Button-1>",goto)
        name.bind("<Button-1>",goto)

    

    # ==================

    def stat_box(
            self,
            parent,
            value,
            label
    ):

        box = Frame(
            parent,
            bg=self.COLORS["card"],
            padx=20,
            pady=20
        )

        box.pack(
            fill=X,
            pady=10
        )

        Label(
            box,
            text=value,
            bg=self.COLORS["card"],
            fg=self.C("text"),
            font=(
                "Segoe UI",
                20,
                "bold"
            )
        ).pack(
            anchor="w"
        )

        Label(
            box,
            text=label,
            bg=self.COLORS["card"],
            fg=self.COLORS["muted"]
        ).pack(
            anchor="w"
        )

    # ==================

    def get_stats(self):

        try:

            with open(
                    STATS,
                    "r"
            ) as f:

                return json.load(
                    f
                )

        except Exception:

            return {

                "encrypted": 0,

                "decrypted": 0

            }

    # ==================


    def save_stats(

        self,

        action,

        filename=""

    ):

        stats = self.user_stats()

        if action == "encrypt":

            stats["encrypted"] += 1

            activity = f"Encrypted {filename}"

        else:

            stats["decrypted"] += 1

            activity = f"Decrypted {filename}"

        self.log_activity(

        activity

        )

        self.save_history(

            action,

            filename

        )


        stats["last_login"] = datetime.now().strftime(

            "%d %b %Y"

        )

        try:

            with open(

                STATS,

                "r"

            ) as f:

                data = json.load(f)

        except Exception:

            data = {}

        data[self.user] = stats

        with open(

            STATS,

            "w"

        ) as f:

            json.dump(

                data,

                f,

                indent=4

            )


    # ==================

    def save_history(

        self,

        action,

        filename

    ):

        try:

            with open(

                "history.json",

                "r"

            ) as f:

                data = json.load(

                    f

                )

        except Exception:

            data=[]

        data.insert(

            0,

            {

                "time":

                datetime.now().strftime(

                    "%d %b %Y • %H:%M"

                ),

                "action":

                action,

                "file":

                filename

            }

        )

        with open(

            "history.json",

            "w"

        ) as f:

            json.dump(

                data,

                f,

                indent=4

            )
    #===================

    def log_activity(

        self,

        action

    ):

        try:

            with open(

                STATS,

                "r"

            ) as f:

                all_data = json.load(f)

        except Exception:

            all_data = {}

        stats = self.user_stats()

        stats["activity"].append(

            {

                "text": action,

                "time":

                datetime.now().strftime(

                    "%I:%M %p"

                ),

                "date":

                datetime.now().strftime(

                    "%d %b %Y"

                )

            }

        )

        all_data[

            self.user

        ] = stats

        with open(

            STATS,

            "w"

        ) as f:

            json.dump(

                all_data,

                f,

                indent=4

            )

    #===================
    #===================


    def load_theme(self):

        try:

            with open(

                "theme.json",

                "r"

            ) as f:

                return json.load(

                    f

                ).get(

                    "theme",

                    "dark"

                )

        except Exception:

            return "dark"

    # ==================
    def save_theme(self):

        with open(

            "theme.json",

            "w"

        ) as f:

            json.dump(

                {

                    "theme":

                    self.theme

                },

                f,

                indent=4

            )

    # ==================

    def load_profile(self):

        if not os.path.exists(PROFILE):

            return {}

        try:

            with open(

                PROFILE,

                "r"

            ) as f:

                data = json.load(f)

        except Exception:

            data = {}

        return data.get(

            self.user,

            {}

        )


    def save_profile(

        self,

        data

    ):

        all_data = {}

        if os.path.exists(PROFILE):

            try:

                with open(

                    PROFILE,

                    "r"

                ) as f:

                    all_data = json.load(f)

            except Exception:

                pass

        all_data[

            self.user

        ] = data

        with open(

            PROFILE,

            "w"

        ) as f:

            json.dump(

                all_data,

                f,

                indent=4

            )

    # ==================
    def load_settings(self):

        defaults = {

            "dark": True,

            "autosave": True,

            "notify": True,

            "secure": True,

            "open_folder": False

        }

        if os.path.exists(SETTINGS):

            try:

                with open(

                    SETTINGS,

                    "r"

                ) as f:

                    data = json.load(f)

                    defaults.update(

                        data.get(

                            self.user,

                            {}

                        )

                    )

            except Exception:

                pass

        return defaults
    # =========================
    def apply_theme(self):

        if self.theme=="dark":

            self.COLORS={

            "bg":"#050d18",

            "panel":"#091425",

            "card":"#0d1a2d",

            "accent":"#00ffaa",

            "text":"white",

            "muted":"#8c96a5",

            "danger":"#ff4d73",

            "row":"#13233a",

            "button":"#0f2038"

            }

        elif self.theme=="light":

            self.COLORS={

            "bg":"#eef2f8",

            "panel":"white",

            "card":"#f7f9fc",

            "accent":"#1877ff",

            "text":"#111827",

            "muted":"#667085",

            "danger":"#ef476f",

            "row":"#e8edf5",

            "button":"#dbe7f5"

            }

        elif self.theme=="cyber":

            self.COLORS={

            "bg":"#03060a",

            "panel":"#080b10",

            "card":"#121722",

            "accent":"#00ffb7",

            "text":"#d7fff6",

            "muted":"#76a4a0",

            "danger":"#ff3c7b",

            "row":"#1a212c",

            "button":"#111827"

            }

        else:

            self.COLORS={

            "bg":"#08111f",

            "panel":"#0d1d31",

            "card":"#132238",

            "accent":"#3bb3ff",

            "text":"white",

            "muted":"#9fb4c9",

            "danger":"#ff557a",

            "row":"#1c3550",

            "button":"#18304a"

            }

        self.root.configure(

            bg=self.COLORS["bg"]

        )

    def save_settings(self):

        data = {}

        if os.path.exists(SETTINGS):

            try:

                with open(

                    SETTINGS,

                    "r"

                ) as f:

                    data = json.load(f)

            except Exception:

                pass


        data[

            self.user

        ] = {

            "dark":

            self.dark.get(),

            "autosave":

            self.auto.get(),

            "notify":

            self.notify.get(),

            "secure":

            self.secure.get(),

            "open_folder":

            self.folder.get()

        }


        with open(

            SETTINGS,

            "w"

        ) as f:

            json.dump(

                data,

                f,

                indent=4

            )

        self.apply_theme()

        self.root.session_start = self.session_start
        for w in self.root.winfo_children():

            w.destroy()

        Dashboard(

            self.root,

            self.user

        )

        data = {}

        if os.path.exists(

            SETTINGS

        ):

            try:

                with open(

                    SETTINGS,

                    "r"

                ) as f:

                    data = json.load(f)

            except Exception:

                pass


        data[

            self.user

        ] = {

            "dark":

            self.dark.get(),

            "autosave":

            self.auto.get(),

            "notify":

            self.notify.get(),

            "secure":

            self.secure.get(),

            "open_folder":

            self.folder.get()

        }


        with open(

            SETTINGS,

            "w"

        ) as f:

            json.dump(

                data,

                f,

                indent=4

            )

    #==================
    def session_time(self):

        elapsed = int(

            time.time()

            -

            self.session_start

        )

        h = elapsed // 3600

        m = (

            elapsed %

            3600

        ) // 60

        s = elapsed % 60

        return (

            f"{h:02}:{m:02}:{s:02}"

        )


    # ==================

    def user_stats(self):

        try:

            with open(STATS,"r") as f:

                all_stats=json.load(f)

        except Exception:

            all_stats={}

        if self.user not in all_stats:

            all_stats[self.user]={

                "encrypted":0,

                "decrypted":0,

                "activity":[

                    "Logged in"

                ],

                "last_login":

                datetime.now().strftime(

                    "%d %b"

                )

            }

            with open(

                STATS,

                "w"

            ) as f:

                json.dump(

                    all_stats,

                    f,

                    indent=4

                )

        return all_stats[self.user]

    # ==================


    def update_session_timer(self):

        if not hasattr(
            self,
            "timer_label"
        ):
            self.root.after(
                1000,
                self.update_session_timer
            )
            return

        elapsed=int(
            time.time()
            -
            self.session_start
        )

        h=elapsed//3600
        m=(elapsed%3600)//60
        s=elapsed%60

        try:

            self.timer_label.config(

                text=
                f"🟢 Active • "
                f"{h:02}:{m:02}:{s:02}"

            )

        except Exception:
            pass

        self.root.after(
            1000,
            self.update_session_timer
        )


    # ======================


    def dashboard(self):

        self.clear()

        self.top()

        status = Frame(

            self.content,

            bg="#0c1c30",

            padx=35,

            pady=25

        )

        status.pack(

            fill=X,

            padx=40

        )

        Label(

            status,

            text="🛡 SYSTEM STATUS : SECURE",

            bg="#0c1c30",

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                22,

                "bold"

            )

        ).pack(

            anchor="w"

        )

        try:
            _score_report = build_security_report(self.user)
            _status_text = (
                f"Security score: {_score_report.score}/{_score_report.max_score} "
                f"({_score_report.percentage}%). "
                + _score_report.recommendations[0]
            )
        except Exception:
            _status_text = "Your encryption environment is healthy and active."

        Label(

            status,

            text=_status_text,

            bg="#0c1c30",

            fg=self.C("text"),

            font=(

                "Segoe UI",

                12

            )

        ).pack(

            anchor="w",

            pady=10

        )

        body = Frame(

            self.content,

            bg=self.COLORS["bg"]

        )

        body.pack(

            fill=BOTH,

            expand=True,

            padx=40,

            pady=30

        )

        left = Frame(

            body,

            bg=self.COLORS["bg"]

        )

        left.pack(

            side=LEFT,

            fill=BOTH,

            expand=True

        )

        right = Frame(

            body,

            bg=self.COLORS["bg"],

            width=400

        )

        right.pack(

            side=RIGHT,

            fill=Y

        )

        # ENCRYPT

        enc = Frame(

            left,

            bg="#06271f",

            padx=40,

            pady=35

        )

        enc.pack(

            fill=X,

            pady=15

        )

        Label(

            enc,

            text="🔒 Encrypt File",

            bg="#06271f",

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                26,

                "bold"

            )

        ).pack()

        Label(

            enc,

            text="Protect files before sharing",

            bg="#06271f",

            fg=self.C("text")

        ).pack()

        Button(

            enc,

            text="Encrypt Now",

            command=self.encrypt,

            bg=self.COLORS["accent"],

            fg="black",

            bd=0,

            width=25,

            height=2

        ).pack(

            pady=25

        )

        # DECRYPT

        dec = Frame(

            left,

            bg="#301220",

            padx=40,

            pady=35

        )

        dec.pack(

            fill=X,

            pady=15

        )

        Label(

            dec,

            text="🔓 Decrypt File",

            bg="#301220",

            fg=self.COLORS["danger"],

            font=(

                "Segoe UI",

                26,

                "bold"

            )

        ).pack()

        Label(

            dec,

            text="Restore encrypted files",

            bg="#301220",

            fg=self.C("text")

        ).pack()

        Button(

            dec,

            text="Decrypt Now",

            command=self.decrypt,

            bg=self.COLORS["danger"],

            fg=self.C("text"),

            bd=0,

            width=25,

            height=2

        ).pack(

            pady=25

        )

        # RIGHT SIDE

        stats=self.user_stats()

        quick=Frame(

        right,

        bg=self.COLORS["bg"]

        )

        quick.pack(

        fill=X

        )

        Label(

        quick,

        text="Quick Stats",

        bg=self.COLORS["bg"],

        fg=self.COLORS["text"],

        font=(

        "Segoe UI",

        18,

        "bold"

        )

        ).pack(

        anchor="w",

        pady=(0,15)

        )

        cards=[

        (

        str(stats["encrypted"]),

        "Encrypted"

        ),

        (

        str(stats["decrypted"]),

        "Decrypted"

        ),

        (

        "AES-256",

        "Security"

        ),

        (

        stats["last_login"],

        "Last Login"

        )

        ]

        for value,label in cards:

            self.stat_box(

                quick,

                value,

                label

            )

        # ACTIVITY

        act = Frame(
            right,
            bg=self.COLORS["card"]
        )

        act.pack(
            fill=BOTH,
            pady=25
        )

        def open_activity(event=None):
            self.activity()

        act.bind(
            "<Button-1>",
            open_activity
        )

        title = Label(
            act,
            text="Recent Activity",
            bg=self.COLORS["card"],
            fg=self.C("text"),
            font=("Segoe UI",16,"bold"),
            cursor="hand2"
        )

        title.pack(
            pady=15
        )

        title.bind(
            "<Button-1>",
            open_activity
        )

        for item in reversed(

        stats["activity"][-5:]

        ):

            if isinstance(

                item,

                dict

            ):

                text = item.get(

                    "text",

                    "Activity"

                )

                timer = (

                    item.get(

                        "time",

                        "--"

                    )

                    +

                    " • "

                    +

                    item.get(

                        "date",

                        "Today"

                    )

                )

            else:

                text = str(

                    item

                )

                timer = (

                    datetime.now()

                    .strftime(

                        "%I:%M %p"

                    )

                )

            row = Label(

                act,

                text=

                f"✓ {text}"

                "\n"

                f"🕒 {timer}",

                bg=self.COLORS["card"],

                fg=self.COLORS["accent"],

                cursor="hand2",

                font=(

                    "Segoe UI",

                    11

                )

            )

            row.pack(

                anchor="w",

                padx=25,

                pady=6

            )

            row.bind(

                "<Button-1>",

                open_activity

            )
        
        #--------------------------
        footer = Frame(

            self.content,

            bg=self.COLORS["card"]

        )

        footer.pack(

            fill=X,

            padx=40,

            pady=20

        )

        Label(

            footer,

            text="Stay safe. Stay secure.",

            bg=self.COLORS["card"],

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                16

            )

        ).pack(

            pady=15

        )
        
        self.page_after(
            50,
            lambda:
            self.canvas.configure(
                scrollregion=
                self.canvas.bbox("all")
            )
        )
        
    # ==================

    def activity(self):

        self.clear()


        page = self.content


        # HEADER

        header = Frame(

            page,

            bg=self.COLORS["bg"]

        )

        header.pack(

            fill=X

        )

        Label(

            header,

            text="📋 Activity Center",

            bg=self.COLORS["bg"],

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                28,

                "bold"

            )

        ).pack(

            side=LEFT

        )

        stats = self.user_stats()

        Label(

            header,

            text=f"{len(stats['activity'])} Events",

            bg=self.COLORS["bg"],

            fg=self.COLORS["muted"],

            font=(

                "Segoe UI",

                12

            )

        ).pack(

            side=RIGHT,

            pady=15

        )

        container = self.content

        # LIVE ACTIVITIES

        items=[]

        for i in reversed(

        stats["activity"]

        ):

            if isinstance(

                i,

                str

            ):

                items.append(

                    {

                        "text":i,

                        "time":"--"

                    }

                )

            else:

                items.append(

                    i

                )

        if not items:

            items=[

                "No activity yet"

            ]

        for index,item in enumerate(items):

            card = Frame(

                container,

                bg=self.C("row"),

                padx=25,

                pady=18

            )

            card.pack(
            fill=X,
            expand=True,
            padx=10,
            pady=8,
            ipady=18
            )

            icon="✓"

            color="#00ffaa"

            text=item["text"].lower()

            if "decrypt" in text:

                icon="🔓"

                color="#ff4d73"

            elif "encrypt" in text:

                icon="🔒"

            elif "password" in text:

                icon="🔑"

            elif "profile" in text:

                icon="👤"

            elif "login" in text:

                icon="🟢"

            Label(

                card,

                text=icon,

                bg=self.C("row"),

                fg=color,

                font=(

                    "Segoe UI",

                    24

                )

            ).pack(

                side=LEFT,

                padx=10

            )

            body = Frame(

                card,

                bg=self.C("row")

            )

            body.pack(
                side=LEFT,
                fill=BOTH,
                expand=True,
                padx=15
            )

            Label(

                body,

                text=item["text"],

                bg=self.C("row"),

                fg=self.C("text"),

                font=(

                    "Segoe UI",

                    13,

                    "bold"

                )

            ).pack(

                anchor="w"

            )

            Label(

                body,

                text=

                f"🕒 {item['time']}"

                "\n"

                f"📅 {item.get('date','Today')}",

                bg=self.C("row"),

                fg=self.COLORS["muted"],

                justify="left",

                font=(

                    "Segoe UI",

                    10

                )

            ).pack(

                anchor="w"

            )

            right = Frame(

                card,

                bg=self.C("row")

            )

            right.pack(

                side=RIGHT,

                padx=15

            )

            Label(

                right,

                text="LIVE",

                bg=self.C("row"),

                fg=self.COLORS["accent"],

                font=(

                    "Segoe UI",

                    10,

                    "bold"

                )

            ).pack(

                anchor="e"

            )

            Label(

                right,

                text=

                item.get(

                    "time",

                    "--"

                ),

                bg=self.C("row"),

                fg=self.C("text"),

                font=(

                    "Segoe UI",

                    11,

                    "bold"

                )

            ).pack(

                anchor="e"

            )

            Label(

                right,

                text=

                item.get(

                    "date",

                    "Today"

                ),

                bg=self.C("row"),

                fg=self.COLORS["muted"],

                font=(

                    "Segoe UI",

                    9

                )

            ).pack(

                anchor="e"

            )
        self.content.update_idletasks()

        try:
            self.canvas.configure(
                scrollregion=
                self.canvas.bbox("all")
            )
        except Exception:
            pass
        
       

    # ==================

    def profile(self):

        self.clear()

        page = self.content
        

        

        # ----------------
        # LEFT PROFILE CARD
        # ----------------

        left = Frame(

            page,

            bg=self.COLORS["card"],

            width=420,

            height=760

        )

        left.pack(

            side=LEFT,

            fill=Y,

            padx=(0,25)

        )

        left.pack_propagate(False)
        photo = self.profile_data.get(

            "photo"

        )

        try:

            if photo and os.path.exists(photo):

                img = Image.open(

                    photo

                )

                img = img.resize(

                    (

                        180,

                        180

                    )

                )

                self.profile_photo = ImageTk.PhotoImage(

                    img

                )

                self.profile_img = Label(

                    left,

                    image=self.profile_photo,

                    bg=self.COLORS["card"]

                )

            else:

                raise Exception()

        except Exception:

            self.profile_img = Label(

                left,

                text="👤",

                bg=self.COLORS["card"],

                fg=self.COLORS["accent"],

                font=(

                    "Segoe UI",

                    100

                )

            )

        self.profile_img.pack(

            pady=20

        )

        self.profile_img.pack(

            pady=20

        )

        Label(

            left,

            text=self.profile_data.get(

                "username",

                self.user

            ),

            bg=self.COLORS["card"],

            fg=self.C("text"),

            font=(

                "Segoe UI",

                24,

                "bold"

            )

        ).pack(

            pady=(0,8)

        )

        Label(

            left,

            text="Premium Secure User",

            bg=self.COLORS["card"],

            fg=self.COLORS["muted"],

            font=(

                "Segoe UI",

                12

            )

        ).pack(

            pady=(0,20)

        )

        Button(

            left,

            text="📷 Upload Profile",

            command=self.upload_profile,

            bg=self.COLORS["accent"],

            fg="black",

            bd=0,

            width=28,

            height=2,

            cursor="hand2"

        ).pack(

            pady=10

        )

        Button(

            left,

            text="✏ Edit Username",

            command=self.edit_username,

            bg=self.COLORS["button"],

            fg=self.C("text"),

            bd=0,

            width=28,

            height=2,

            cursor="hand2"

        ).pack(

            pady=10

        )

        Button(

            left,

            text="🔑 Change Password",

            command=self.change_password,

            bg=self.COLORS["danger"],

            fg="white",

            bd=0,

            width=28,

            height=2,

            cursor="hand2"

        ).pack(

            pady=10

        )

        Button(

            left,

            text="🧹 Clear Activity",

            command=self.clear_activity_data,

            bg="#ff9800",

            fg="white",

            bd=0,

            width=28,

            height=2,

            cursor="hand2"

        ).pack(

            pady=10

        )

        # ----------------
        # RIGHT OVERVIEW
        # ----------------

        right = Frame(

            page,

            bg=self.COLORS["card"]

        )

        right.pack(

            side=LEFT,

            fill=BOTH,

            expand=True

        )

        Label(

            right,

            text="Account Overview",

            bg=self.COLORS["card"],

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                28,

                "bold"

            )

        ).pack(

            pady=25

        )

        stats_data = self.user_stats()

        files_total = (

            stats_data["encrypted"]

            +

            stats_data["decrypted"]

        )

        activity_count = len(

            stats_data["activity"]

        )

        security_score = min(

            100,

            85 + activity_count

        )

        stats = [

            (

                "Files Protected",

                str(

                    files_total

                )

            ),

            (

                "Encrypted Files",

                str(

                    stats_data["encrypted"]

                )

            ),

            (

                "Security Health",

                f"{security_score}%"

            ),

            (

                "Last Login",

                stats_data.get(

                    "last_login",

                    "Today"

                )

            ),

            (

                "Recent Activity",

                f"{activity_count} Events"

            ),

            (

                "Storage Used",

                f"{files_total*12} MB"

            )

        ]

        for title,value in stats:

            row = Frame(

                right,

                bg=self.C("row"),

                padx=25,

                pady=18

            )

            row.pack(

                fill=X,

                padx=35,

                pady=8

            )

            left_side = Frame(

                row,

                bg=self.C("row")

            )

            left_side.pack(

                side=LEFT

            )

            Label(

                left_side,

                text=title,

                bg=self.C("row"),

                fg=self.C("text"),

                font=(

                    "Segoe UI",

                    13,

                    "bold"

                )

            ).pack(

                anchor="w"

            )

            Label(

                left_side,

                text={

                    "Files Protected":

                    "Files secured in account",

                    "Encrypted Files":

                    "Encrypted successfully",

                    "Security Health":

                    "Protection status",

                    "Last Login":

                    "Last account access",

                    "Recent Activity":

                    "Recent account actions",

                    "Storage Used":

                    "Protected storage"

                }.get(

                    title,

                    ""

                ),

                bg=self.C("row"),

                fg=self.COLORS["muted"],

                font=(

                    "Segoe UI",

                    10

                )

            ).pack(

                anchor="w"

            )

            Label(

                row,

                text=value,

                bg=self.C("row"),

                fg=self.COLORS["accent"],

                font=(

                    "Segoe UI",

                    18,

                    "bold"

                )

            ).pack(

                side=RIGHT

            )

        Label(

            right,

            text="✓ Synced • Saved • Secure",

            bg=self.COLORS["card"],

            fg=self.COLORS["muted"],

            font=(

                "Segoe UI",

                11

            )

        ).pack(

            pady=20

        )

        self.page_after(
            50,
            lambda:
            self.canvas.configure(
                scrollregion=
                self.canvas.bbox("all")
            )
        )
       
    #--------------------
    def edit_username(self):

        win = Toplevel()

        win.title(

            "Change Username"

        )

        win.geometry(

            "350x200"

        )

        e = Entry(

            win,

            font=(

                "Segoe UI",

                14

            )

        )

        e.pack(

            pady=30

        )


        def save():

            new = e.get()

            if new:

                renamed = user_repo.rename_user(self.user, new)

                if not renamed:
                    win.destroy()
                    return

                self.profile_data["username"] = new

                self.user = new

                self.save_profile(

                    self.profile_data

                )

                win.destroy()

                self.profile()


        Button(

            win,

            text="Save",

            command=save

        ).pack()

    def change_password(self):

        win = Toplevel()

        win.geometry(

            "350x250"

        )

        e = Entry(

            win,

            show="●"

        )

        e.pack(

            pady=20

        )


        def save():

            pwd = e.get()

            if pwd:

                user_repo.update_password_hash(

                    self.user,

                    hash_password(pwd)

                )
                self.log_activity(

                "🔑 Password Changed"

                )

                win.destroy()


        Button(

            win,

            text="Update",

            command=save

        ).pack()


    def upload_profile(self):

        from tkinter import filedialog

        file = filedialog.askopenfilename(

            filetypes=[

                (

                    "Images",

                    "*.png *.jpg *.jpeg"

                )

            ]

        )

        if not file:

            return

        self.profile_data[

            "photo"

        ] = file

        self.save_profile(

            self.profile_data

        )

        self.log_activity(

        "👤 Username Changed"

        )
        self.log_activity(

        "📷 Profile Picture Updated"

        )

        self.profile()
    # ==================

    def clear_activity_data(self):

        from tkinter import messagebox

        confirm = messagebox.askyesno(

            "Reset Activity",

            "Clear all activity and history?\n\nThis cannot be undone."

        )

        if not confirm:
            return

        try:

            stats = self.user_stats()

            stats["activity"] = []

            stats["encrypted"] = 0

            stats["decrypted"] = 0

            stats["last_login"] = (

                datetime.now()

                .strftime(

                    "%d %b %Y"

                )

            )

            try:

                with open(

                    STATS,

                    "r"

                ) as f:

                    data = json.load(f)

            except Exception:

                data = {}

            data[

                self.user

            ] = stats

            with open(

                STATS,

                "w"

            ) as f:

                json.dump(

                    data,

                    f,

                    indent=4

                )

            with open(

                "history.json",

                "w"

            ) as f:

                json.dump(

                    [],

                    f

                )

            self.log_activity(

                "🧹 Activity Reset"

            )

            messagebox.showinfo(

                "Success",

                "Activity cleared"

            )

            self.profile()

        except Exception as e:

            messagebox.showerror(

                "Error",

                str(e)

            )
    # ==================

    def settings(self):

        self.clear()

        cfg = self.load_settings()

        self.dark = BooleanVar(

            value=cfg["dark"]

        )

        self.auto = BooleanVar(

            value=cfg["autosave"]

        )

        self.notify = BooleanVar(

            value=cfg["notify"]

        )

        self.secure = BooleanVar(

            value=cfg["secure"]

        )

        self.folder = BooleanVar(

            value=cfg["open_folder"]

        )

        panel = Frame(

            self.content,

            bg=self.COLORS["card"]

        )

        panel.pack(

            padx=50,

            pady=40,

            fill=BOTH,

            expand=True

        )

        Label(

            panel,

            text="⚙ Settings",

            bg=self.COLORS["card"],

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                30,

                "bold"

            )

        ).pack(

            pady=30

        )

        items = [

            (

                "💾 Auto Save",

                self.auto

            ),

            (

                "🔔 Notifications",

                self.notify

            ),

            (

                "🛡 Secure Mode",

                self.secure

            ),

            (

                "📂 Open Folder Automatically",

                self.folder

            )

        ]

        for text,var in items:

            row = Frame(

                panel,

                bg=self.COLORS["card"],

                pady=20

            )

            row.pack(

                fill=X,

                padx=50,

                pady=10

            )

            Checkbutton(

                row,

                text=text,

                variable=var,

                command=self.save_settings,

                bg=self.COLORS["card"],

                fg=self.COLORS["text"],

                selectcolor=self.COLORS["card"],

                activebackground=self.C("row"),

                font=(

                    "Segoe UI",

                    13

                )

            ).pack(

                anchor="w",

                padx=20

            )

        Button(

            panel,

            text="Reset Profile",

            bg=self.COLORS["danger"],

            fg=self.COLORS["text"],

            bd=0,

            width=22,

            height=2,

            command=lambda:[

                os.remove(PROFILE)

                if os.path.exists(PROFILE)

                else None,

                self.profile()

            ]

        ).pack(

            pady=30

        )

        # ======================
        # APP THEME
        # ======================

        theme_area = Frame(

        panel,

        bg=self.COLORS["card"]

        )

        theme_area.pack(

        anchor="w",

        padx=40,

        pady=(25,10)

        )


        Label(

        theme_area,

        text="🎨 Theme",

        bg=self.COLORS["card"],

        fg=self.COLORS["accent"],

        font=(

        "Segoe UI",

        13,

        "bold"

        )

        ).pack(

        anchor="w",

        pady=(0,8)

        )

        selected = StringVar()

        selected.set(

        self.theme.capitalize()

        )


        def switch_theme(choice):

            self.theme = choice.lower()

            self.save_theme()

            for w in self.root.winfo_children():

                w.destroy()

            Dashboard(

                self.root,

                self.user

            )


        menu = OptionMenu(

        theme_area,

        selected,

        "Dark",

        "Light",

        "Cyber",

        "Ocean",

        command=switch_theme

        )

        menu.config(

        width=14,

        font=(

        "Segoe UI",

        10

        ),

        bg=self.COLORS["button"],

        fg=self.C("text"),

        bd=0,

        highlightthickness=0

        )

        menu["menu"].config(

        bg=self.COLORS["card"],

        fg=self.C("text")

        )

        menu.pack()

        self.page_after(
            50,
            lambda:
            self.canvas.configure(
                scrollregion=
                self.canvas.bbox("all")
            )
        )

        

    def history(self):

        self.clear()


        page = self.content
        Label(

            page,

            text="📁 File History",

            bg=self.COLORS["bg"],

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                28,

                "bold"

            )

        ).pack(
            anchor="w"
        )

        try:

            with open(

                "history.json",

                "r"

            ) as f:

                logs=json.load(f)

        except Exception:

            logs=[]

        body = Frame(

            page,

            bg=self.COLORS["bg"]

        )

        body.pack(

            fill=BOTH,

            expand=True,

            padx=30,
            pady=20

        )

        if not logs:

            Label(

                body,

                text="No file history yet",

                bg=self.COLORS["bg"],

                fg=self.COLORS["muted"]

            ).pack()

            return

        for item in logs:

            card = Frame(

                body,

                bg=self.C("row"),

                padx=25,

                pady=18

            )

            card.pack(

                fill=X,

                pady=8

            )

            Label(

                card,

                text=item["action"],

                bg=self.C("row"),

                fg=self.COLORS["accent"],

                font=(

                    "Segoe UI",

                    14,

                    "bold"

                )

            ).pack(
                anchor="w"
            )

            Label(

                card,

                text=item["file"],

                bg=self.C("row"),

                fg=self.C("text")

            ).pack(
                anchor="w"
            )

            Label(

                card,

                text=item["time"],

                bg=self.C("row"),

                fg=self.COLORS["muted"]

            ).pack(
                anchor="e"
            )
        self.page_after(
            50,
            lambda:
            self.canvas.configure(
                scrollregion=
                self.canvas.bbox("all")
            )
        )
    # ==================

    def security_center(self):

        self.clear()

        page = self.content

        Label(
            page,
            text="🛡 Security Center",
            bg=self.COLORS["bg"],
            fg=self.COLORS["accent"],
            font=("Segoe UI", 28, "bold")
        ).pack(anchor="w", pady=(0, 10))

        try:
            report = build_security_report(self.user)
        except Exception:
            Label(
                page,
                text="Unable to load security posture right now.",
                bg=self.COLORS["bg"],
                fg=self.COLORS["danger"],
                font=("Segoe UI", 13)
            ).pack(anchor="w")
            return

        score_frame = Frame(page, bg=self.COLORS["card"])
        score_frame.pack(fill=X, pady=(0, 20))

        Label(
            score_frame,
            text=f"Security Score: {report.score}/{report.max_score} ({report.percentage}%)",
            bg=self.COLORS["card"],
            fg=self.COLORS["accent"],
            font=("Segoe UI", 18, "bold")
        ).pack(anchor="w", padx=20, pady=15)

        def render_section(title, checks):
            section = Frame(page, bg=self.COLORS["card"])
            section.pack(fill=X, pady=8)

            Label(
                section,
                text=title,
                bg=self.COLORS["card"],
                fg=self.C("text"),
                font=("Segoe UI", 14, "bold")
            ).pack(anchor="w", padx=20, pady=(12, 4))

            for key, info in checks.items():
                if not isinstance(info, dict) or "status" not in info:
                    continue
                icon = "✓" if info["status"] else "⚠"
                color = self.COLORS["accent"] if info["status"] else self.COLORS["danger"]
                Label(
                    section,
                    text=f"{icon} {info.get('label', key)}",
                    bg=self.COLORS["card"],
                    fg=color,
                    font=("Segoe UI", 12)
                ).pack(anchor="w", padx=30, pady=2)

            Label(section, text="", bg=self.COLORS["card"]).pack(pady=4)

        render_section("Authentication", report.authentication)
        render_section("Encryption", report.encryption)
        render_section("Audit", report.audit)

        mfa_row = Frame(page, bg=self.COLORS["bg"])
        mfa_row.pack(anchor="w", pady=(4, 12))

        mfa_on = report.authentication.get("mfa", {}).get("status", False)
        Button(
            mfa_row,
            text="Disable MFA" if mfa_on else "🔑 Enable MFA",
            command=self.mfa_setup,
            bg=self.COLORS["accent"] if not mfa_on else self.COLORS["card"],
            fg="white" if not mfa_on else self.C("text"),
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 11, "bold"),
            padx=15,
            pady=8
        ).pack(side=LEFT)

        rec_section = Frame(page, bg=self.COLORS["card"])
        rec_section.pack(fill=X, pady=8)

        Label(
            rec_section,
            text="Recommendations",
            bg=self.COLORS["card"],
            fg=self.C("text"),
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=20, pady=(12, 4))

        for rec in report.recommendations:
            Label(
                rec_section,
                text=f"• {rec}",
                bg=self.COLORS["card"],
                fg=self.COLORS["muted"],
                font=("Segoe UI", 11),
                wraplength=700,
                justify="left"
            ).pack(anchor="w", padx=30, pady=3)

        Label(rec_section, text="", bg=self.COLORS["card"]).pack(pady=4)

        # --- Security Alerts (real, event-derived) ---
        alerts_section = Frame(page, bg=self.COLORS["card"])
        alerts_section.pack(fill=X, pady=8)

        Label(
            alerts_section,
            text="Security Alerts",
            bg=self.COLORS["card"],
            fg=self.C("text"),
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=20, pady=(12, 4))

        try:
            active_alerts = run_alerts(self.user)
        except Exception:
            active_alerts = []

        severity_colors = {
            "CRITICAL": self.COLORS["danger"],
            "HIGH": self.COLORS["danger"],
            "MEDIUM": "#e6b800",
            "LOW": self.COLORS["muted"],
            "INFO": self.COLORS["muted"],
        }

        if not active_alerts:
            Label(
                alerts_section,
                text="No active security alerts.",
                bg=self.COLORS["card"],
                fg=self.COLORS["accent"],
                font=("Segoe UI", 11)
            ).pack(anchor="w", padx=30, pady=(2, 10))
        else:
            for alert in active_alerts:
                Label(
                    alerts_section,
                    text=f"[{alert.severity}] {alert.title}",
                    bg=self.COLORS["card"],
                    fg=severity_colors.get(alert.severity, self.C("text")),
                    font=("Segoe UI", 12, "bold")
                ).pack(anchor="w", padx=30, pady=(6, 0))
                Label(
                    alerts_section,
                    text=alert.detail,
                    bg=self.COLORS["card"],
                    fg=self.COLORS["muted"],
                    font=("Segoe UI", 10),
                    wraplength=650,
                    justify="left"
                ).pack(anchor="w", padx=30, pady=(0, 4))

        Label(alerts_section, text="", bg=self.COLORS["card"]).pack(pady=4)

        # --- Security Health Check (real, deterministic) ---
        health_section = Frame(page, bg=self.COLORS["card"])
        health_section.pack(fill=X, pady=8)

        header_row = Frame(health_section, bg=self.COLORS["card"])
        header_row.pack(fill=X, padx=20, pady=(12, 4))

        Label(
            header_row,
            text="Security Health Check",
            bg=self.COLORS["card"],
            fg=self.C("text"),
            font=("Segoe UI", 14, "bold")
        ).pack(side=LEFT)

        try:
            health_report = run_health_check()
        except Exception:
            health_report = None

        health_status_colors = {
            HC_PASS: self.COLORS["accent"],
            HC_WARNING: "#e6b800",
            HC_FAIL: self.COLORS["danger"],
        }

        if health_report is None:
            Label(
                health_section,
                text="Unable to run health check.",
                bg=self.COLORS["card"],
                fg=self.COLORS["danger"],
                font=("Segoe UI", 11)
            ).pack(anchor="w", padx=30, pady=(2, 10))
        else:
            Label(
                header_row,
                text=health_report.overall_status,
                bg=self.COLORS["card"],
                fg=health_status_colors.get(health_report.overall_status, self.C("text")),
                font=("Segoe UI", 12, "bold")
            ).pack(side=RIGHT)

            for item in health_report.items:
                icon = {"PASS": "✓", "WARNING": "⚠", "FAIL": "✗"}.get(item.status, "•")
                Label(
                    health_section,
                    text=f"{icon} {item.name}: {item.status}",
                    bg=self.COLORS["card"],
                    fg=health_status_colors.get(item.status, self.C("text")),
                    font=("Segoe UI", 12)
                ).pack(anchor="w", padx=30, pady=(4, 0))
                Label(
                    health_section,
                    text=item.detail,
                    bg=self.COLORS["card"],
                    fg=self.COLORS["muted"],
                    font=("Segoe UI", 10),
                    wraplength=650,
                    justify="left"
                ).pack(anchor="w", padx=30, pady=(0, 2))

        Label(health_section, text="", bg=self.COLORS["card"]).pack(pady=4)

        self.page_after(
            50,
            lambda: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

    # ==================

    def file_scanner(self):

        self.clear()

        page = self.content

        Label(
            page,
            text="🕵 File Security Analyzer",
            bg=self.COLORS["bg"],
            fg=self.COLORS["accent"],
            font=("Segoe UI", 28, "bold")
        ).pack(anchor="w", pady=(0, 6))

        Label(
            page,
            text="Not an antivirus. Flags suspicious characteristics such as double "
                 "extensions or content/extension mismatches for your review.",
            bg=self.COLORS["bg"],
            fg=self.COLORS["muted"],
            font=("Segoe UI", 11),
            wraplength=700,
            justify="left"
        ).pack(anchor="w", pady=(0, 20))

        result_holder = {"path": None, "result": None}
        result_frame = Frame(page, bg=self.COLORS["card"])
        result_frame.pack(fill=X, pady=10)

        def render_result():
            for w in result_frame.winfo_children():
                w.destroy()

            result = result_holder["result"]
            if result is None:
                return

            risk_colors = {
                "LOW": self.COLORS["accent"],
                "MEDIUM": "#e6b800",
                "HIGH": self.COLORS["danger"],
                "CRITICAL": self.COLORS["danger"],
            }

            Label(
                result_frame,
                text=f"File: {result.filename}",
                bg=self.COLORS["card"],
                fg=self.C("text"),
                font=("Segoe UI", 13, "bold")
            ).pack(anchor="w", padx=20, pady=(15, 4))

            Label(
                result_frame,
                text=f"SHA-256: {result.sha256}",
                bg=self.COLORS["card"],
                fg=self.COLORS["muted"],
                font=("Segoe UI", 10)
            ).pack(anchor="w", padx=20, pady=2)

            Label(
                result_frame,
                text=f"Risk: {result.risk_level}  (score {result.score}/100)",
                bg=self.COLORS["card"],
                fg=risk_colors.get(result.risk_level, self.C("text")),
                font=("Segoe UI", 13, "bold")
            ).pack(anchor="w", padx=20, pady=6)

            for reason in result.reasons:
                Label(
                    result_frame,
                    text=f"• {reason}",
                    bg=self.COLORS["card"],
                    fg=self.COLORS["muted"],
                    font=("Segoe UI", 11),
                    wraplength=650,
                    justify="left"
                ).pack(anchor="w", padx=30, pady=2)

            btn_row = Frame(result_frame, bg=self.COLORS["card"])
            btn_row.pack(anchor="w", padx=20, pady=15)

            def do_quarantine():
                try:
                    quarantine_svc.quarantine_file(
                        result_holder["path"],
                        result.sha256,
                        result.risk_level,
                        result.reasons,
                        username=self.user,
                    )
                    log_event(
                        audit_events.FILE_SCANNED,
                        username=self.user,
                        result="info",
                        object_id=result.filename,
                        metadata={"risk_level": result.risk_level, "action": "quarantined"},
                    )
                    messagebox.showinfo("Quarantined", "File moved to quarantine.")
                    self.file_scanner()
                except Exception as e:
                    messagebox.showerror("Error", f"Unable to quarantine file: {e}")

            if result.risk_level in ("HIGH", "CRITICAL"):
                Button(
                    btn_row,
                    text="🧪 Quarantine",
                    command=do_quarantine,
                    bg=self.COLORS["danger"],
                    fg="white",
                    bd=0,
                    cursor="hand2",
                    font=("Segoe UI", 11, "bold"),
                    padx=15,
                    pady=8
                ).pack(side=LEFT, padx=(0, 10))

            Button(
                btn_row,
                text="Scan Another",
                command=self.file_scanner,
                bg=self.COLORS["card"],
                fg=self.C("text"),
                bd=1,
                cursor="hand2",
                font=("Segoe UI", 11),
                padx=15,
                pady=8
            ).pack(side=LEFT)

        def pick_and_scan():
            path = filedialog.askopenfilename()
            if not path:
                return
            try:
                with open(path, "rb") as f:
                    data = f.read()
                result = analyze_file(os.path.basename(path), data)
                result_holder["path"] = path
                result_holder["result"] = result

                log_event(
                    audit_events.FILE_SCANNED,
                    username=self.user,
                    result="info",
                    object_id=result.filename,
                    metadata={"risk_level": result.risk_level, "score": result.score},
                )
                render_result()
            except Exception as e:
                messagebox.showerror("Error", f"Unable to scan file: {e}")

        Button(
            page,
            text="📂 Select File to Scan",
            command=pick_and_scan,
            bg=self.COLORS["accent"],
            fg="white",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 12, "bold"),
            padx=20,
            pady=10
        ).pack(anchor="w")

        self.page_after(
            50,
            lambda: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

    # ==================

    def quarantine_page(self):

        self.clear()

        page = self.content

        Label(
            page,
            text="🧪 Quarantine",
            bg=self.COLORS["bg"],
            fg=self.COLORS["accent"],
            font=("Segoe UI", 28, "bold")
        ).pack(anchor="w", pady=(0, 20))

        try:
            items = quarantine_svc.list_items(state="quarantined")
        except Exception:
            items = []

        if not items:
            Label(
                page,
                text="No quarantined files.",
                bg=self.COLORS["bg"],
                fg=self.COLORS["muted"],
                font=("Segoe UI", 13)
            ).pack(anchor="w")
            return

        for item in items:

            row = Frame(page, bg=self.COLORS["card"])
            row.pack(fill=X, pady=6)

            info = Frame(row, bg=self.COLORS["card"])
            info.pack(side=LEFT, fill=X, expand=True, padx=20, pady=12)

            Label(
                info,
                text=f"{item.original_filename}  ·  {item.risk_level}",
                bg=self.COLORS["card"],
                fg=self.C("text"),
                font=("Segoe UI", 13, "bold")
            ).pack(anchor="w")

            Label(
                info,
                text=f"Quarantined: {item.created_at}   SHA-256: {item.sha256[:16]}...",
                bg=self.COLORS["card"],
                fg=self.COLORS["muted"],
                font=("Segoe UI", 10)
            ).pack(anchor="w")

            if item.reasons:
                Label(
                    info,
                    text="; ".join(item.reasons),
                    bg=self.COLORS["card"],
                    fg=self.COLORS["muted"],
                    font=("Segoe UI", 10),
                    wraplength=500,
                    justify="left"
                ).pack(anchor="w")

            btns = Frame(row, bg=self.COLORS["card"])
            btns.pack(side=RIGHT, padx=20)

            def make_restore(qid=item.quarantine_id):
                def _restore():
                    dest = filedialog.asksaveasfilename(initialfile=item.original_filename)
                    if not dest:
                        return
                    try:
                        quarantine_svc.restore_item(qid, dest, username=self.user)
                        messagebox.showinfo("Restored", "File restored.")
                        self.quarantine_page()
                    except Exception as e:
                        messagebox.showerror("Error", str(e))
                return _restore

            def make_delete(qid=item.quarantine_id, name=item.original_filename):
                def _delete():
                    confirm = messagebox.askyesno(
                        "Confirm Permanent Delete",
                        f"Permanently delete '{name}' from quarantine? This cannot be undone."
                    )
                    if not confirm:
                        return
                    try:
                        quarantine_svc.delete_item(qid, username=self.user)
                        self.quarantine_page()
                    except Exception as e:
                        messagebox.showerror("Error", str(e))
                return _delete

            Button(
                btns,
                text="Restore",
                command=make_restore(),
                bg=self.COLORS["card"],
                fg=self.C("text"),
                bd=1,
                cursor="hand2",
                font=("Segoe UI", 10),
                padx=10,
                pady=6
            ).pack(side=LEFT, padx=4)

            Button(
                btns,
                text="Delete",
                command=make_delete(),
                bg=self.COLORS["danger"],
                fg="white",
                bd=0,
                cursor="hand2",
                font=("Segoe UI", 10, "bold"),
                padx=10,
                pady=6
            ).pack(side=LEFT, padx=4)

        self.page_after(
            50,
            lambda: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

    # ==================

    def reports_page(self):

        self.clear()

        page = self.content

        Label(
            page,
            text="📊 Security Reports",
            bg=self.COLORS["bg"],
            fg=self.COLORS["accent"],
            font=("Segoe UI", 28, "bold")
        ).pack(anchor="w", pady=(0, 20))

        Label(
            page,
            text="Generates a report from real account activity: authentication, "
                 "encryption/decryption, integrity, and quarantine events.",
            bg=self.COLORS["bg"],
            fg=self.COLORS["muted"],
            font=("Segoe UI", 11),
            wraplength=700,
            justify="left"
        ).pack(anchor="w", pady=(0, 20))

        def export(fmt):
            try:
                data = report_service.build_report_data(self.user)
            except Exception as e:
                messagebox.showerror("Error", f"Unable to build report: {e}")
                return

            ext = {"json": ".json", "csv": ".csv", "pdf": ".pdf"}[fmt]
            save = filedialog.asksaveasfilename(
                defaultextension=ext,
                initialfile=f"securevault_report{ext}"
            )
            if not save:
                return

            try:
                if fmt == "json":
                    with open(save, "w") as f:
                        f.write(report_service.export_json(data))
                elif fmt == "csv":
                    with open(save, "w", newline="") as f:
                        f.write(report_service.export_csv(data))
                else:
                    report_service.export_pdf(data, save)

                messagebox.showinfo("Success", f"Report saved to {save}")
            except Exception as e:
                messagebox.showerror("Error", f"Unable to save report: {e}")

        btn_row = Frame(page, bg=self.COLORS["bg"])
        btn_row.pack(anchor="w")

        for label, fmt in [("Export JSON", "json"), ("Export CSV", "csv"), ("Export PDF", "pdf")]:
            Button(
                btn_row,
                text=label,
                command=lambda f=fmt: export(f),
                bg=self.COLORS["accent"],
                fg="white",
                bd=0,
                cursor="hand2",
                font=("Segoe UI", 12, "bold"),
                padx=18,
                pady=10
            ).pack(side=LEFT, padx=(0, 10))

        self.page_after(
            50,
            lambda: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

    # ==================

    def mfa_setup(self):

        self.clear()

        page = self.content

        Label(
            page,
            text="🔑 Multi-Factor Authentication",
            bg=self.COLORS["bg"],
            fg=self.COLORS["accent"],
            font=("Segoe UI", 26, "bold")
        ).pack(anchor="w", pady=(0, 16))

        already_enabled = mfa_service.is_mfa_enabled(self.user)

        if already_enabled:

            Label(
                page,
                text="MFA is currently ENABLED for your account.",
                bg=self.COLORS["bg"],
                fg=self.COLORS["accent"],
                font=("Segoe UI", 13, "bold")
            ).pack(anchor="w", pady=(0, 16))

            Label(
                page,
                text="Enter your current password to disable MFA.",
                bg=self.COLORS["bg"],
                fg=self.COLORS["muted"],
                font=("Segoe UI", 11)
            ).pack(anchor="w", pady=(0, 6))

            pwd_entry = Entry(page, show="●", width=30)
            pwd_entry.pack(anchor="w", pady=(0, 12))

            def do_disable():
                if mfa_service.disable_mfa(self.user, pwd_entry.get()):
                    log_event(audit_events.MFA_DISABLED, username=self.user, result="success")
                    messagebox.showinfo("MFA Disabled", "Multi-factor authentication has been disabled.")
                    self.security_center()
                else:
                    messagebox.showerror("Error", "Incorrect password.")

            Button(
                page,
                text="Disable MFA",
                command=do_disable,
                bg=self.COLORS["danger"],
                fg="white",
                bd=0,
                cursor="hand2",
                font=("Segoe UI", 12, "bold"),
                padx=18,
                pady=10
            ).pack(anchor="w")

            self.page_after(50, lambda: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
            return

        # --- Enrollment flow ---
        secret, uri = mfa_service.begin_mfa_setup(self.user)

        Label(
            page,
            text="1. Add this secret to an authenticator app (Google Authenticator, "
                 "Authy, 1Password, etc.):",
            bg=self.COLORS["bg"],
            fg=self.C("text"),
            font=("Segoe UI", 12),
            wraplength=650,
            justify="left"
        ).pack(anchor="w", pady=(0, 6))

        secret_box = Entry(page, width=40, justify="center", font=("Consolas", 13))
        secret_box.insert(0, secret)
        secret_box.config(state="readonly")
        secret_box.pack(anchor="w", pady=(0, 16))

        Label(
            page,
            text="Or add this provisioning URI directly (QR-code rendering isn't "
                 "available in this build):",
            bg=self.COLORS["bg"],
            fg=self.COLORS["muted"],
            font=("Segoe UI", 10),
            wraplength=650,
            justify="left"
        ).pack(anchor="w")

        uri_box = Entry(page, width=70, font=("Consolas", 9))
        uri_box.insert(0, uri)
        uri_box.config(state="readonly")
        uri_box.pack(anchor="w", pady=(0, 20))

        Label(
            page,
            text="2. Enter the 6-digit code from your app to confirm setup:",
            bg=self.COLORS["bg"],
            fg=self.C("text"),
            font=("Segoe UI", 12)
        ).pack(anchor="w", pady=(0, 6))

        code_entry = Entry(page, width=12, font=("Segoe UI", 14), justify="center")
        code_entry.pack(anchor="w", pady=(0, 16))

        def do_confirm():
            try:
                recovery_codes = mfa_service.confirm_mfa_setup(self.user, code_entry.get())
            except mfa_service.MfaError as e:
                messagebox.showerror("Invalid Code", str(e))
                return

            log_event(audit_events.MFA_ENABLED, username=self.user, result="success")

            codes_text = "\n".join(recovery_codes)
            messagebox.showinfo(
                "MFA Enabled",
                "MFA is now enabled. Save these one-time recovery codes somewhere "
                "safe -- each can be used once if you lose access to your authenticator "
                f"app. They will not be shown again:\n\n{codes_text}"
            )
            self.security_center()

        Button(
            page,
            text="Confirm and Enable MFA",
            command=do_confirm,
            bg=self.COLORS["accent"],
            fg="white",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 12, "bold"),
            padx=18,
            pady=10
        ).pack(anchor="w")

        self.page_after(50, lambda: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

    # ==================

    def about(self):

        self.clear()


        page = self.content
        # HEADER

        top = Frame(

            page,

            bg=self.COLORS["card"]

        )

        top.pack(

            fill=X,

            pady=(0,20)

        )

        Label(

            top,

            text="🛡",

            bg=self.COLORS["card"],

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                60

            )

        ).pack(
            pady=(25,0)
        )

        Label(

            top,

            text="SecureVault",

            bg=self.COLORS["card"],

            fg=self.COLORS["text"],

            font=(

                "Segoe UI",

                26,

                "bold"

            )

        ).pack()

        Label(

            top,

            text="Version 4.0 • Enterprise Security Platform",

            bg=self.COLORS["card"],

            fg=self.COLORS["muted"],

            font=(

                "Segoe UI",

                11

            )

        ).pack(
            pady=(5,25)
        )

        # INFO GRID

        grid = Frame(

            page,

            bg=self.COLORS["bg"]

        )

        grid.pack(

            fill=BOTH,

            expand=True

        )

        cards = [

            (

                "🔐 Security",

                [

                    "AES-256 Encryption",

                    "Password Protection",

                    "Secure Authentication"

                ]

            ),

            (

                "⚡ Features",

                [

                    "File Recovery",

                    "Dashboard Analytics",

                    "Activity Tracking"

                ]

            ),

            (

                "🛠 Technology",

                [

                    "Python",

                    "Tkinter",

                    "Cryptography"

                ]

            ),

            (

                "🚀 Roadmap",

                [

                    "Cloud Sync",

                    "Mobile App",

                    "Team Workspace"

                ]

            )

        ]

        for i,(title,items) in enumerate(cards):

            card = Frame(

                grid,

                bg=self.COLORS["card"],

                width=420,

                height=250

            )

            card.grid(

                row=i//2,

                column=i%2,

                padx=15,

                pady=15,

                sticky="nsew"

            )

            card.grid_propagate(False)

            Label(

                card,

                text=title,

                bg=self.COLORS["card"],

                fg=self.COLORS["accent"],

                font=(

                    "Segoe UI",

                    18,

                    "bold"

                )

            ).pack(
                pady=20
            )

            for item in items:

                Label(

                    card,

                    text=f"✓ {item}",

                    bg=self.COLORS["card"],

                    fg=self.COLORS["text"],

                    anchor="w",

                    font=(

                        "Segoe UI",

                        12

                    )

                ).pack(

                    anchor="w",

                    padx=35,

                    pady=5

                )

        grid.grid_columnconfigure(
            0,
            weight=1
        )

        grid.grid_columnconfigure(
            1,
            weight=1
        )
        
        #============================

        # ----------------
        # HOW TO USE
        # ----------------

        guide = Frame(

            page,

            bg=self.COLORS["card"]

        )

        guide.pack(

            fill=X,

            pady=20

        )

        Label(

            guide,

            text="🚀 Quick Start",

            bg=self.COLORS["card"],

            fg=self.COLORS["accent"],

            font=(

                "Segoe UI",

                20,

                "bold"

            )

        ).pack(

            pady=(20,15)

        )

        steps = [

        "1. Create account and login",

        "2. Upload or choose a file",

        "3. Use Encrypt File to secure data",

        "4. Use Decrypt File to restore files",

        "5. Track actions in Activity Center",

        "6. Manage profile and settings"

        ]

        for step in steps:

            row = Frame(

                guide,

                bg=self.COLORS["card"]

            )

            row.pack(

                fill=X,

                padx=40,

                pady=6

            )

            Label(

                row,

                text="✓",

                bg=self.COLORS["card"],

                fg=self.COLORS["accent"],

                font=(

                    "Segoe UI",

                    14,

                    "bold"

                )

            ).pack(

                side=LEFT

            )

            Label(

                row,

                text=step,

                bg=self.COLORS["card"],

                fg=self.C("text"),

                font=(

                    "Segoe UI",

                    12

                )

            ).pack(

                side=LEFT,

                padx=10

            )

        Label(

            guide,

            text="Your files stay protected using AES-256 encryption and account-based activity tracking.",

            bg=self.COLORS["card"],

            fg=self.COLORS["muted"],

            wraplength=900,

            justify="center",

            font=(

                "Segoe UI",

                11

            )

        ).pack(

            pady=(15,25)

        )


        # FOOTER

        footer = Frame(

            page,

            bg=self.COLORS["card"]

        )

        footer.pack(

            fill=X,

            pady=20

        )

        Label(

            footer,

            text="System Status: ● Secure",

            bg=self.COLORS["card"],

            fg="#22c55e",

            font=(

                "Segoe UI",

                12,

                "bold"

            )

        ).pack(
            pady=10
        )

        Label(

            footer,

            text="© 2026 SecureVault",

            bg=self.COLORS["card"],

            fg=self.COLORS["muted"]

        ).pack(
            pady=(0,15)
        )

        self.page_after(
            50,
            lambda:
            self.canvas.configure(
                scrollregion=
                self.canvas.bbox("all")
            )
        )   
    # ==================

    def encrypt(self):

        self.clear()

        page=self.content

        frame=Frame(
            page,
            bg=self.COLORS["bg"]
        )

        frame.pack(
            fill=BOTH,
            expand=True
        )

        def done(file_name="file"):

            self.save_stats(
                "encrypt",
                file_name
            )

            self.dashboard()

        EncryptPage(
            frame,
            done,
            username=self.user
        )

    # ==================

    def decrypt(self):

        self.clear()

        page=self.content

        frame=Frame(
            page,
            bg=self.COLORS["bg"]
        )

        frame.pack(
            fill=BOTH,
            expand=True
        )

        def done(file_name="file"):

            self.save_stats(
                "decrypt",
                file_name
            )

            self.dashboard()

        DecryptPage(
            frame,
            done,
            username=self.user
        )

    # ======================

    def reset_activity(self,event=None):

        self.last_activity=time.time()


# ======================

    def monitor_activity(self):

        if self._destroyed:
            return

        inactive = time.time() - self.last_activity

        if inactive > (self.lock_minutes * 60):
            self.lock_screen()
            return

        self._monitor_job = self.root.after(5000, self.monitor_activity)


    # ======================

    def lock_screen(self):

        if self._destroyed:
            return
        self._destroyed = True

        for job_name in ("_monitor_job", "_session_timer_job"):
            job = getattr(self, job_name, None)
            if job is not None:
                try:
                    self.root.after_cancel(job)
                except Exception:
                    pass
                setattr(self, job_name, None)

        for job in self._page_after_ids:
            try:
                self.root.after_cancel(job)
            except Exception:
                pass
        self._page_after_ids.clear()

        session_id = getattr(self.root, "securevault_session_id", None)
        if session_id:
            try:
                session_service.lock_session(session_id)
            except Exception:
                pass

        log_event(audit_events.SESSION_LOCKED, username=self.user, result="info")
        self.log_activity("🔒 Session Locked")

        for w in self.root.winfo_children():
            w.destroy()

        from auth import LoginApp
        app = LoginApp(self.root)
        app.show_login()
        app.user.delete(0, END)
        app.user.insert(0, self.user)
        app.user.config(state="disabled")
        app.password.focus()

    # ======================

    def logout(self):

        if self._destroyed:
            return
        self._destroyed = True

        for job_name in ("_monitor_job", "_session_timer_job"):
            job = getattr(self, job_name, None)
            if job is not None:
                try:
                    self.root.after_cancel(job)
                except Exception:
                    pass
                setattr(self, job_name, None)

        for job in self._page_after_ids:
            try:
                self.root.after_cancel(job)
            except Exception:
                pass
        self._page_after_ids.clear()

        session_id = getattr(self.root, "securevault_session_id", None)
        if session_id:
            try:
                session_service.end_session(session_id)
            except Exception:
                pass
            self.root.securevault_session_id = None

        log_event(audit_events.LOGOUT, username=self.user, result="info")

        self.log_activity(

        "⎋ Logged Out"

        )

        if hasattr(

            self.root,

            "session_start"

        ):

            del self.root.session_start

        for w in self.root.winfo_children():

            w.destroy()

        LoginApp(

            self.root

        )
    
    def app_close(self):

        try:

            self.log_activity(
                "⎋ Logged Out"
            )

        except Exception:
            pass

        self.root.destroy()


# ==================
#
# NOTE: this module used to have a direct top-level launch block that
# constructed the Dashboard with a hardcoded default account and no
# session or second-factor check at all -- a full authentication bypass
# if this file were ever executed directly instead of the app's real
# entry point. That block has been removed. The only supported entry
# point is `python app.py`, which goes through the login screen's
# password -> MFA -> session enforcement path. 