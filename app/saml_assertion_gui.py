"""
SAML Assertion Generator - Standalone GUI Application
Generates signed SAML 2.0 assertions for SuccessFactors BizX OAuth token requests.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

from saml_assertion_builder import generate_signed_assertion


def get_app_dir() -> str:
    """Get the directory where the app/script is located."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def load_properties(filepath: str) -> dict:
    """Parse a Java-style .properties file into a dict."""
    props = {}
    if not os.path.isfile(filepath):
        return props
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                props[key.strip()] = value.strip()
    return props


class SAMLAssertionApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SAML Assertion Generator")
        self.root.resizable(True, True)
        self.root.minsize(600, 520)

        self._build_ui()
        self._auto_load_properties()

    def _build_ui(self):
        # Main frame with padding
        main = ttk.Frame(self.root, padding=12)
        main.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)

        row = 0

        # Title
        title = ttk.Label(main, text="SAML Assertion Generator", font=("Segoe UI", 14, "bold"))
        title.grid(row=row, column=0, columnspan=3, pady=(0, 10), sticky="w")
        row += 1

        # Input fields
        fields = [
            ("Token URL:", "token_url"),
            ("Client ID:", "client_id"),
            ("User ID:", "user_id"),
            ("User Name:", "user_name"),
            ("Expire (min):", "expire_minutes"),
        ]

        self.entries = {}
        for label_text, field_name in fields:
            ttk.Label(main, text=label_text).grid(row=row, column=0, sticky="w", pady=3)
            entry = ttk.Entry(main, width=60)
            entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=3, padx=(8, 0))
            self.entries[field_name] = entry
            row += 1

        # Default expire minutes
        self.entries["expire_minutes"].insert(0, "10")

        # Private Key (multiline)
        ttk.Label(main, text="Private Key:").grid(row=row, column=0, sticky="nw", pady=3)
        self.private_key_text = scrolledtext.ScrolledText(main, width=60, height=6, wrap=tk.WORD,
                                                          font=("Consolas", 9))
        self.private_key_text.grid(row=row, column=1, columnspan=2, sticky="ew", pady=3, padx=(8, 0))
        row += 1

        # Buttons frame
        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=row, column=0, columnspan=3, pady=10)

        self.load_btn = ttk.Button(btn_frame, text="Load Properties", command=self._browse_properties)
        self.load_btn.pack(side="left", padx=4)

        self.generate_btn = ttk.Button(btn_frame, text="Generate Assertion", command=self._generate)
        self.generate_btn.pack(side="left", padx=4)

        self.copy_btn = ttk.Button(btn_frame, text="Copy to Clipboard", command=self._copy_to_clipboard,
                                   state="disabled")
        self.copy_btn.pack(side="left", padx=4)

        self.clear_btn = ttk.Button(btn_frame, text="Clear", command=self._clear_output)
        self.clear_btn.pack(side="left", padx=4)
        row += 1

        # Output area
        ttk.Label(main, text="Generated Assertion:").grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1

        self.output_text = scrolledtext.ScrolledText(main, width=60, height=10, wrap=tk.WORD,
                                                     font=("Consolas", 9), state="disabled")
        self.output_text.grid(row=row, column=0, columnspan=3, sticky="nsew", pady=(4, 0))
        main.rowconfigure(row, weight=1)

        # Status bar
        row += 1
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(8, 0))

    def _auto_load_properties(self):
        """Auto-load SAMLAssertion.properties if it exists in the app directory or parent."""
        app_dir = get_app_dir()
        candidates = [
            os.path.join(app_dir, "SAMLAssertion.properties"),
            os.path.join(os.path.dirname(app_dir), "SAMLAssertion.properties"),
        ]
        for path in candidates:
            props = load_properties(path)
            if props:
                self._fill_from_properties(props)
                self.status_var.set(f"Loaded properties from: {path}")
                return

    def _browse_properties(self):
        """Open file dialog to select a .properties file."""
        filepath = filedialog.askopenfilename(
            title="Select Properties File",
            filetypes=[("Properties files", "*.properties"), ("All files", "*.*")],
            initialdir=get_app_dir(),
        )
        if filepath:
            props = load_properties(filepath)
            if props:
                self._fill_from_properties(props)
                self.status_var.set(f"Loaded: {filepath}")
            else:
                messagebox.showwarning("Empty File", "No properties found in the selected file.")

    def _fill_from_properties(self, props: dict):
        mapping = {
            "tokenUrl": "token_url",
            "clientId": "client_id",
            "userId": "user_id",
            "userName": "user_name",
            "expireInMinutes": "expire_minutes",
        }
        for prop_key, field_name in mapping.items():
            value = props.get(prop_key, "")
            if value and field_name in self.entries:
                entry = self.entries[field_name]
                entry.delete(0, tk.END)
                entry.insert(0, value)

        private_key = props.get("privateKey", "")
        if private_key:
            self.private_key_text.delete("1.0", tk.END)
            self.private_key_text.insert("1.0", private_key)

    def _generate(self):
        token_url = self.entries["token_url"].get().strip()
        client_id = self.entries["client_id"].get().strip()
        user_id = self.entries["user_id"].get().strip()
        user_name = self.entries["user_name"].get().strip()
        private_key = self.private_key_text.get("1.0", tk.END).strip()

        try:
            expire_minutes = int(self.entries["expire_minutes"].get().strip() or "10")
            if expire_minutes <= 0:
                expire_minutes = 10
        except ValueError:
            expire_minutes = 10

        # Handle userName fallback (matching Java logic lines 67-71)
        use_username_as_user_id = False
        if (not user_id) and user_name:
            user_id = user_name
            use_username_as_user_id = True

        # Validate required fields
        missing = []
        if not token_url:
            missing.append("Token URL")
        if not client_id:
            missing.append("Client ID")
        if not user_id:
            missing.append("User ID (or User Name)")
        if not private_key:
            missing.append("Private Key")
        if missing:
            messagebox.showerror("Missing Fields", "Please provide:\n• " + "\n• ".join(missing))
            return

        self.status_var.set("Generating assertion...")
        self.root.update_idletasks()

        try:
            result = generate_signed_assertion(
                client_id=client_id,
                user_id=user_id,
                token_url=token_url,
                private_key_string=private_key,
                expire_in_minutes=expire_minutes,
                use_username_as_user_id=use_username_as_user_id,
            )
            self._set_output(result)
            self.copy_btn.config(state="normal")
            self.status_var.set("Assertion generated successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate assertion:\n{e}")
            self.status_var.set("Generation failed.")

    def _set_output(self, text: str):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", text)
        self.output_text.config(state="disabled")

    def _copy_to_clipboard(self):
        self.output_text.config(state="normal")
        content = self.output_text.get("1.0", tk.END).strip()
        self.output_text.config(state="disabled")
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.status_var.set("Copied to clipboard!")

    def _clear_output(self):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")
        self.copy_btn.config(state="disabled")
        self.status_var.set("Ready")


def main():
    root = tk.Tk()
    SAMLAssertionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
