import tkinter as tk
from tkinter import messagebox
from auth import LoginApp

if __name__ == "__main__":

    root = tk.Tk()

    root.title("SecureVault — Enterprise File Security")

    try:
        root.iconbitmap("assets/icon.ico")
    except Exception as e:
        print(e)

    root.geometry("1600x900")
    root.minsize(1180, 760)
    root.configure(bg="#071018")
    root.minsize(1180, 760)

    def report_callback_exception(exc, val, tb):
        # Tkinter otherwise prints callback exceptions and may leave the
        # application looking blank. Show a recoverable message instead.
        import traceback
        traceback.print_exception(exc, val, tb)
        try:
            messagebox.showerror(
                "SecureVault Error",
                "An unexpected application error occurred. "
                "Your protected data was not intentionally exposed.\n\n"
                f"{exc.__name__}: {val}"
            )
        except Exception:
            pass

    root.report_callback_exception = report_callback_exception
    LoginApp(root)

    root.mainloop()