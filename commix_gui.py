import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import subprocess
import threading
import queue
import os
import sys
import re

class CommixGUI:
    def __init__(self, master):
        self.master = master
        master.title("Commix GUI")
        master.geometry("1200x900")
        master.resizable(True, True)
        master.grid_rowconfigure(0, weight=1)
        master.grid_rowconfigure(1, weight=0)
        master.grid_rowconfigure(2, weight=0)
        master.grid_rowconfigure(3, weight=0)
        master.grid_rowconfigure(4, weight=1)
        master.grid_rowconfigure(5, weight=0) # Added for the new footer label
        master.grid_columnconfigure(0, weight=1)

        self.commix_process = None
        self.output_queue = queue.Queue()
        self.input_queue = queue.Queue()
        self.search_start_index = "1.0"

        self.style = ttk.Style()
        self.style.theme_use('clam') # Start with clam, then customize

        # Define Sea Theme Colors
        self.colors = {
            "bg_main": "#E0F2F7",       # Light Cyan/Sky Blue
            "bg_frame": "#B2EBF2",      # Light Blue
            "bg_notebook": "#80DEEA",   # Cyan
            "fg_text": "#01579B",       # Dark Blue
            "fg_highlight": "#00BCD4",  # Turquoise
            "button_bg": "#00BCD4",     # Turquoise
            "button_fg": "white",
            "output_bg": "#002633",     # Very Dark Blue/Navy
            "output_fg": "#E0F2F7",     # Light Cyan
            "status_bar_bg": "#00BCD4", # Turquoise
            "status_bar_fg": "white",
            "border_color": "#00BCD4"   # Turquoise for borders
        }

        # Configure the theme
        self.master.config(bg=self.colors["bg_main"]) # Set root window background

        self.style.configure('TFrame', background=self.colors["bg_frame"])
        self.style.configure('TLabel', background=self.colors["bg_frame"], foreground=self.colors["fg_text"])
        self.style.configure('TLabelframe', background=self.colors["bg_frame"], foreground=self.colors["fg_text"], bordercolor=self.colors["border_color"])
        self.style.configure('TLabelframe.Label', background=self.colors["bg_frame"], foreground=self.colors["fg_text"])
        self.style.configure('TButton', background=self.colors["button_bg"], foreground=self.colors["button_fg"], font=('Segoe UI', 10, 'bold'))
        self.style.map('TButton', background=[('active', self.colors["fg_highlight"])]) # Button hover effect

        self.style.configure('TEntry', fieldbackground="white", foreground=self.colors["fg_text"], bordercolor=self.colors["border_color"])
        self.style.configure('TScrolledtext', background="white", foreground=self.colors["fg_text"]) # For help popups

        # Notebook specific styling
        self.style.configure('TNotebook', background=self.colors["bg_notebook"], bordercolor=self.colors["border_color"])
        self.style.configure('TNotebook.Tab', background=self.colors["bg_notebook"], foreground=self.colors["fg_text"],
                             lightcolor=self.colors["bg_notebook"], darkcolor=self.colors["bg_notebook"],
                             bordercolor=self.colors["border_color"])
        self.style.map('TNotebook.Tab', background=[('selected', self.colors["bg_frame"])],
                       foreground=[('selected', self.colors["fg_text"])])

        self.style.configure('TCheckbutton', background=self.colors["bg_frame"], foreground=self.colors["fg_text"])
        self.style.configure('TRadiobutton', background=self.colors["bg_frame"], foreground=self.colors["fg_text"])
        self.style.configure('TCombobox', fieldbackground="white", foreground=self.colors["fg_text"], selectbackground="white", selectforeground=self.colors["fg_text"])


        # --- Notebook (Tabs) ---
        self.notebook = ttk.Notebook(master)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # --- General Tab ---
        self.general_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.general_frame, text="General")
        self._create_general_tab(self.general_frame)

        # --- Target Tab ---
        self.target_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.target_frame, text="Target")
        self._create_target_tab(self.target_frame)

        # --- Request Tab ---
        self.request_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.request_frame, text="Request")
        self._create_request_tab(self.request_frame)

        # --- Enumeration Tab ---
        self.enumeration_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.enumeration_frame, text="Enumeration")
        self._create_enumeration_tab(self.enumeration_frame)

        # --- File Access Tab ---
        self.file_access_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.file_access_frame, text="File Access")
        self._create_file_access_tab(self.file_access_frame)

        # --- Modules Tab ---
        self.modules_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.modules_frame, text="Modules")
        self._create_modules_tab(self.modules_frame)

        # --- Injection Tab ---
        self.injection_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.injection_frame, text="Injection")
        self._create_injection_tab(self.injection_frame)

        # --- Detection Tab ---
        self.detection_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.detection_frame, text="Detection")
        self._create_detection_tab(self.detection_frame)

        # --- Miscellaneous Tab ---
        self.misc_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.misc_frame, text="Miscellaneous")
        self._create_misc_tab(self.misc_frame)

        # --- Additional Arguments ---
        self.additional_args_frame = ttk.LabelFrame(master, text="Additional Arguments (for advanced options not listed above)", padding="10 10 10 10")
        self.additional_args_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.additional_args_frame.grid_columnconfigure(0, weight=1)
        self.additional_args_text = scrolledtext.ScrolledText(self.additional_args_frame, height=4, width=80, font=("Consolas", 10),
                                                              bg=self.colors["output_bg"], fg=self.colors["output_fg"]) # Themed
        self.additional_args_text.grid(row=0, column=0, sticky="nsew")

        # --- Buttons Frame ---
        self.button_frame = ttk.Frame(master, padding="10 0 10 5")
        self.button_frame.grid(row=2, column=0, sticky="ew")

        self.run_button = ttk.Button(self.button_frame, text="Run Commix", command=self.run_commix)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(self.button_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # --- Status Bar ---
        self.status_bar = ttk.Label(master, text="Ready", relief=tk.SUNKEN, anchor=tk.W,
                                    background=self.colors["status_bar_bg"], foreground=self.colors["status_bar_fg"]) # Themed
        self.status_bar.grid(row=3, column=0, sticky="ew")

        # --- Output Frame ---
        self.output_frame = ttk.LabelFrame(master, text="Commix Output", padding="10 10 10 10")
        self.output_frame.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.output_frame.grid_rowconfigure(1, weight=1)
        self.output_frame.grid_columnconfigure(0, weight=1)

        # Search functionality for output
        self.search_frame = ttk.Frame(self.output_frame)
        self.search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        self.search_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(self.search_frame, text="Search:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.search_entry = ttk.Entry(self.search_frame, width=50)
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        self.search_entry.bind("<Return>", self.search_output)
        ttk.Button(self.search_frame, text="Search", command=self.search_output).grid(row=0, column=2, sticky="e", padx=(0, 5))
        ttk.Button(self.search_frame, text="Clear Search", command=self.clear_search_highlight).grid(row=0, column=3, sticky="e")

        self.output_text = scrolledtext.ScrolledText(self.output_frame, wrap=tk.WORD,
                                                     bg=self.colors["output_bg"], fg=self.colors["output_fg"], # Themed
                                                     font=("Consolas", 10), height=30)
        self.output_text.grid(row=1, column=0, sticky="nsew")
        self.output_text.config(state=tk.DISABLED)

        self.output_text.tag_configure("highlight", background="yellow", foreground="black")

        # Interactive input widgets (initially hidden)
        self.interactive_input_frame = ttk.Frame(self.output_frame)
        self.interactive_input_frame.grid_columnconfigure(1, weight=1)
        self.interactive_input_label = ttk.Label(self.interactive_input_frame, text="Commix input:")
        self.interactive_input_entry = ttk.Entry(self.interactive_input_frame, width=50)
        self.interactive_input_send_button = ttk.Button(self.interactive_input_frame, text="Send", command=self.send_input_to_commix)

        self.interactive_input_label.grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.interactive_input_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        self.interactive_input_send_button.grid(row=0, column=2, sticky="e")
        self.interactive_input_entry.bind("<Return>", lambda event: self.send_input_to_commix())

        # --- "Created by" Label ---
        self.created_by_label = ttk.Label(master, text="Created by khedr0x00",
                                          background=self.colors["status_bar_bg"], foreground=self.colors["status_bar_fg"],
                                          anchor=tk.E, font=('Segoe UI', 9, 'italic')) # Themed and styled
        self.created_by_label.grid(row=5, column=0, sticky="ew", padx=10, pady=(5, 10))


        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.master.after(100, self.process_queue)

    def _create_input_field(self, parent_frame, label_text, row, entry_name, col=0, width=40, is_checkbox=False, var_name=None, help_text=None, is_dropdown=False, options=None):
        if is_checkbox:
            var = tk.BooleanVar()
            setattr(self, var_name, var)
            chk = ttk.Checkbutton(parent_frame, text=label_text, variable=var)
            chk.grid(row=row, column=col, sticky="w", pady=2)
            if help_text:
                help_button = ttk.Button(parent_frame, text="?", width=2, command=lambda t=help_text: self._show_help_popup(t))
                help_button.grid(row=row, column=col + 1, sticky="w", padx=(5, 0))
            return chk
        elif is_dropdown:
            label = ttk.Label(parent_frame, text=label_text)
            label.grid(row=row, column=col, sticky="w", pady=2, padx=(0, 5))
            var = tk.StringVar()
            setattr(self, var_name, var)
            dropdown = ttk.Combobox(parent_frame, textvariable=var, values=options, state="readonly", width=width)
            dropdown.grid(row=row, column=col+1, sticky="ew", pady=2)
            if help_text:
                help_button = ttk.Button(parent_frame, text="?", width=2, command=lambda t=help_text: self._show_help_popup(t))
                help_button.grid(row=row, column=col + 2, sticky="w", padx=(5, 0))
            return dropdown
        else:
            label = ttk.Label(parent_frame, text=label_text)
            label.grid(row=row, column=col, sticky="w", pady=2, padx=(0, 5))
            entry = ttk.Entry(parent_frame, width=width)
            entry.grid(row=row, column=col+1, sticky="ew", pady=2)
            setattr(self, entry_name, entry)
            if help_text:
                help_button = ttk.Button(parent_frame, text="?", width=2, command=lambda t=help_text: self._show_help_popup(t))
                help_button.grid(row=row, column=col + 2, sticky="w", padx=(5, 0))
            return entry

    def _show_help_popup(self, help_text):
        popup = tk.Toplevel(self.master)
        popup.title("Help")
        popup.transient(self.master)
        popup.grab_set()

        main_x = self.master.winfo_x()
        main_y = self.master.winfo_y()
        main_width = self.master.winfo_width()
        main_height = self.master.winfo_height()

        popup_width = 500
        popup_height = 300
        popup_x = main_x + (main_width // 2) - (popup_width // 2)
        popup_y = main_y + (main_height // 2) - (popup_height // 2)
        popup.geometry(f"{popup_width}x{popup_height}+{popup_x}+{popup_y}")
        popup.resizable(False, False)

        # Use ttk.Frame for background of popup
        popup_frame = ttk.Frame(popup, padding="10 10 10 10")
        popup_frame.pack(expand=True, fill="both")

        text_widget = scrolledtext.ScrolledText(popup_frame, wrap=tk.WORD, font=("Consolas", 10), width=60, height=15,
                                                bg="white", fg=self.colors["fg_text"]) # Themed
        text_widget.pack(expand=True, fill="both", padx=5, pady=5)
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)

        close_button = ttk.Button(popup_frame, text="Close", command=popup.destroy)
        close_button.pack(pady=5)

    def _create_general_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Verbosity Level (-v):", row, "verbose_entry", width=10,
                                 help_text="Verbosity level (0-4, Default: 0).")
        row += 1
        self._create_input_field(parent_frame, "Output Directory (--output-dir):", row, "output_dir_entry", width=60,
                                 help_text="Set custom output directory path.")
        row += 1
        self._create_input_field(parent_frame, "Session File (-s):", row, "session_file_entry", width=60,
                                 help_text="Load session from a stored (.sqlite) file.")
        row += 1
        self._create_input_field(parent_frame, "Flush Session (--flush-session):", row, None, is_checkbox=True, var_name="flush_session_var",
                                 help_text="Flush session files for current target.")
        row += 1
        self._create_input_field(parent_frame, "Ignore Session (--ignore-session):", row, None, is_checkbox=True, var_name="ignore_session_var",
                                 help_text="Ignore results stored in session file.")
        row += 1
        self._create_input_field(parent_frame, "Traffic File (-t):", row, "traffic_file_entry", width=60,
                                 help_text="Log all HTTP traffic into a textual file.")
        row += 1
        self._create_input_field(parent_frame, "Time Limit (--time-limit):", row, "time_limit_entry", width=20,
                                 help_text="Run with a time limit in seconds (e.g. 3600).")
        row += 1
        self._create_input_field(parent_frame, "Batch Mode (--batch):", row, None, is_checkbox=True, var_name="batch_var",
                                 help_text="Never ask for user input, use the default behaviour.")
        row += 1
        self._create_input_field(parent_frame, "Skip Heuristics (--skip-heuristics):", row, None, is_checkbox=True, var_name="skip_heuristics_var",
                                 help_text="Skip heuristic detection for code injection.")
        row += 1
        self._create_input_field(parent_frame, "Codec (--codec):", row, "codec_entry", width=20,
                                 help_text="Force codec for character encoding (e.g. 'ascii').")
        row += 1
        self._create_input_field(parent_frame, "Charset (--charset):", row, "charset_entry", width=40,
                                 help_text="Time-related injection charset (e.g. '0123456789abcdef').")
        row += 1
        self._create_input_field(parent_frame, "Check Internet (--check-internet):", row, None, is_checkbox=True, var_name="check_internet_var",
                                 help_text="Check internet connection before assessing the target.")
        row += 1
        self._create_input_field(parent_frame, "Answers (--answers):", row, "answers_entry", width=60,
                                 help_text="Set predefined answers (e.g. 'quit=N,follow=N').")

    def _create_target_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "URL (-u):", row, "url_entry", width=60,
                                 help_text="Target URL.")
        row += 1
        self._create_input_field(parent_frame, "URL Reload (--url-reload):", row, None, is_checkbox=True, var_name="url_reload_var",
                                 help_text="Reload target URL after command execution.")
        row += 1
        self._create_input_field(parent_frame, "Log File (-l):", row, "logfile_entry", width=60,
                                 help_text="Parse target from HTTP proxy log file.")
        row += 1
        self._create_input_field(parent_frame, "Bulk File (-m):", row, "bulkfile_entry", width=60,
                                 help_text="Scan multiple targets given in a textual file.")
        row += 1
        self._create_input_field(parent_frame, "Request File (-r):", row, "requestfile_entry", width=60,
                                 help_text="Load HTTP request from a file.")
        row += 1
        self._create_input_field(parent_frame, "Crawl Depth (--crawl):", row, "crawldepth_entry", width=10,
                                 help_text="Crawl the website starting from the target URL (Default: 1).")
        row += 1
        self._create_input_field(parent_frame, "Crawl Exclude (--crawl-exclude):", row, "crawl_exclude_entry", width=60,
                                 help_text="Regexp to exclude pages from crawling (e.g. 'logout').")
        row += 1
        self._create_input_field(parent_frame, "Sitemap URL (-x):", row, "sitemap_url_entry", width=60,
                                 help_text="Parse target(s) from remote sitemap(.xml) file.")
        row += 1
        self._create_input_field(parent_frame, "HTTP Method (--method):", row, "method_entry", width=20,
                                 help_text="Force usage of given HTTP method (e.g. 'PUT').")

    def _create_request_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "POST Data (-d, --data):", row, "data_entry", width=60,
                                 help_text="Data string to be sent through POST.")
        row += 1
        self._create_input_field(parent_frame, "Host (--host):", row, "host_entry", width=60,
                                 help_text="HTTP Host header.")
        row += 1
        self._create_input_field(parent_frame, "Referer (--referer):", row, "referer_entry", width=60,
                                 help_text="HTTP Referer header.")
        row += 1
        self._create_input_field(parent_frame, "User-Agent (--user-agent):", row, "user_agent_entry", width=60,
                                 help_text="HTTP User-Agent header.")
        row += 1
        self._create_input_field(parent_frame, "Random Agent (--random-agent):", row, None, is_checkbox=True, var_name="random_agent_var",
                                 help_text="Use a randomly selected HTTP User-Agent header.")
        row += 1
        self._create_input_field(parent_frame, "Parameter Delimiter (--param-del):", row, "param_del_entry", width=10,
                                 help_text="Set character for splitting parameter values.")
        row += 1
        self._create_input_field(parent_frame, "Cookie (--cookie):", row, "cookie_entry", width=60,
                                 help_text="HTTP Cookie header.")
        row += 1
        self._create_input_field(parent_frame, "Cookie Delimiter (--cookie-del):", row, "cookie_del_entry", width=10,
                                 help_text="Set character for splitting cookie values.")
        row += 1
        self._create_input_field(parent_frame, "Header (-H, --header):", row, "header_entry", width=60,
                                 help_text="Extra header (e.g. 'X-Forwarded-For: 127.0.0.1').")
        row += 1
        self._create_input_field(parent_frame, "Headers (--headers):", row, "headers_entry", width=60,
                                 help_text="Extra headers (e.g. 'Accept-Language: fr\\nETag: 123').")
        row += 1
        self._create_input_field(parent_frame, "Proxy (--proxy):", row, "proxy_entry", width=60,
                                 help_text="Use a proxy to connect to the target URL.")
        row += 1
        self._create_input_field(parent_frame, "Tor (--tor):", row, None, is_checkbox=True, var_name="tor_var",
                                 help_text="Use the Tor network.")
        row += 1
        self._create_input_field(parent_frame, "Tor Port (--tor-port):", row, "tor_port_entry", width=10,
                                 help_text="Set Tor proxy port (Default: 8118).")
        row += 1
        self._create_input_field(parent_frame, "Tor Check (--tor-check):", row, None, is_checkbox=True, var_name="tor_check_var",
                                 help_text="Check to see if Tor is used properly.")
        row += 1
        self._create_input_field(parent_frame, "Auth URL (--auth-url):", row, "auth_url_entry", width=60,
                                 help_text="Login panel URL.")
        row += 1
        self._create_input_field(parent_frame, "Auth Data (--auth-data):", row, "auth_data_entry", width=60,
                                 help_text="Login parameters and data.")
        row += 1
        self._create_input_field(parent_frame, "Auth Type (--auth-type):", row, None, is_dropdown=True, var_name="auth_type_var", options=["Basic", "Digest", "Bearer"],
                                 help_text="HTTP authentication type (Basic, Digest, Bearer).")
        row += 1
        self._create_input_field(parent_frame, "Auth Credentials (--auth-cred):", row, "auth_cred_entry", width=60,
                                 help_text="HTTP authentication credentials (e.g. 'admin:admin').")
        row += 1
        self._create_input_field(parent_frame, "Abort Code (--abort-code):", row, "abort_code_entry", width=20,
                                 help_text="Abort on (problematic) HTTP error code(s) (e.g. 401).")
        row += 1
        self._create_input_field(parent_frame, "Ignore Code (--ignore-code):", row, "ignore_code_entry", width=20,
                                 help_text="Ignore (problematic) HTTP error code(s) (e.g. 401).")
        row += 1
        self._create_input_field(parent_frame, "Force SSL (--force-ssl):", row, None, is_checkbox=True, var_name="force_ssl_var",
                                 help_text="Force usage of SSL/HTTPS.")
        row += 1
        self._create_input_field(parent_frame, "Ignore Proxy (--ignore-proxy):", row, None, is_checkbox=True, var_name="ignore_proxy_var",
                                 help_text="Ignore system default proxy settings.")
        row += 1
        self._create_input_field(parent_frame, "Ignore Redirects (--ignore-redirects):", row, None, is_checkbox=True, var_name="ignore_redirects_var",
                                 help_text="Ignore redirection attempts.")
        row += 1
        self._create_input_field(parent_frame, "Timeout (--timeout):", row, "timeout_entry", width=10,
                                 help_text="Seconds to wait before timeout connection (Default: 30).")
        row += 1
        self._create_input_field(parent_frame, "Retries (--retries):", row, "retries_entry", width=10,
                                 help_text="Retries when the connection timeouts (Default: 3).")
        row += 1
        self._create_input_field(parent_frame, "Drop Set-Cookie (--drop-set-cookie):", row, None, is_checkbox=True, var_name="drop_set_cookie_var",
                                 help_text="Ignore Set-Cookie header from response.")

    def _create_enumeration_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        enum_frame = ttk.LabelFrame(parent_frame, text="Enumeration Options", padding="10")
        enum_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=5)
        enum_frame.grid_columnconfigure(1, weight=1)
        enum_row = 0
        self._create_input_field(enum_frame, "Retrieve Everything (--all):", enum_row, None, is_checkbox=True, var_name="enum_all_var",
                                 help_text="Retrieve everything.")
        enum_row += 1
        self._create_input_field(enum_frame, "Current User (--current-user):", enum_row, None, is_checkbox=True, var_name="current_user_var",
                                 help_text="Retrieve current user name.")
        enum_row += 1
        self._create_input_field(enum_frame, "Hostname (--hostname):", enum_row, None, is_checkbox=True, var_name="hostname_var",
                                 help_text="Retrieve current hostname.")
        enum_row += 1
        self._create_input_field(enum_frame, "Is Root (--is-root):", enum_row, None, is_checkbox=True, var_name="is_root_var",
                                 help_text="Check if the current user have root privileges.")
        enum_row += 1
        self._create_input_field(enum_frame, "Is Admin (--is-admin):", enum_row, None, is_checkbox=True, var_name="is_admin_var",
                                 help_text="Check if the current user have admin privileges.")
        enum_row += 1
        self._create_input_field(enum_frame, "System Info (--sys-info):", enum_row, None, is_checkbox=True, var_name="sys_info_var",
                                 help_text="Retrieve system information.")
        enum_row += 1
        self._create_input_field(enum_frame, "Users (--users):", enum_row, None, is_checkbox=True, var_name="users_var",
                                 help_text="Retrieve system users.")
        enum_row += 1
        self._create_input_field(enum_frame, "Passwords (--passwords):", enum_row, None, is_checkbox=True, var_name="passwords_var",
                                 help_text="Retrieve system users password hashes.")
        enum_row += 1
        self._create_input_field(enum_frame, "Privileges (--privileges):", enum_row, None, is_checkbox=True, var_name="privileges_var",
                                 help_text="Retrieve system users privileges.")
        enum_row += 1
        self._create_input_field(enum_frame, "PS Version (--ps-version):", enum_row, None, is_checkbox=True, var_name="ps_version_var",
                                 help_text="Retrieve PowerShell's version number.")

    def _create_file_access_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "File Read (--file-read):", row, "file_read_entry", width=60,
                                 help_text="Read a file from the target host.")
        row += 1
        self._create_input_field(parent_frame, "File Write (--file-write):", row, "file_write_entry", width=60,
                                 help_text="Write to a file on the target host.")
        row += 1
        self._create_input_field(parent_frame, "File Upload (--file-upload):", row, "file_upload_entry", width=60,
                                 help_text="Upload a file on the target host.")
        row += 1
        self._create_input_field(parent_frame, "File Destination (--file-dest):", row, "file_dest_entry", width=60,
                                 help_text="Host's absolute filepath to write and/or upload to.")

    def _create_modules_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Shellshock (--shellshock):", row, None, is_checkbox=True, var_name="shellshock_var",
                                 help_text="The 'shellshock' injection module.")

    def _create_injection_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Test Parameter (-p):", row, "test_parameter_entry", width=60,
                                 help_text="Testable parameter(s).")
        row += 1
        self._create_input_field(parent_frame, "Skip Parameter (--skip):", row, "skip_parameter_entry", width=60,
                                 help_text="Skip testing for given parameter(s).")
        row += 1
        self._create_input_field(parent_frame, "Suffix (--suffix):", row, "suffix_entry", width=60,
                                 help_text="Injection payload suffix string.")
        row += 1
        self._create_input_field(parent_frame, "Prefix (--prefix):", row, "prefix_entry", width=60,
                                 help_text="Injection payload prefix string.")
        row += 1
        self._create_input_field(parent_frame, "Technique (--technique):", row, "technique_entry", width=20,
                                 help_text="Specify injection technique(s) to use (e.g., 'B,E,U,Q,T,S').")
        row += 1
        self._create_input_field(parent_frame, "Skip Technique (--skip-technique):", row, "skip_technique_entry", width=20,
                                 help_text="Specify injection technique(s) to skip (e.g., 'B,E').")
        row += 1
        self._create_input_field(parent_frame, "Max Length (--maxlen):", row, "maxlen_entry", width=10,
                                 help_text="Set the max length of output for time-related injection techniques (Default: 1000 chars).")
        row += 1
        self._create_input_field(parent_frame, "Delay (--delay):", row, "delay_entry", width=10,
                                 help_text="Seconds to delay between each HTTP request.")
        row += 1
        self._create_input_field(parent_frame, "Time Sec (--time-sec):", row, "timesec_entry", width=10,
                                 help_text="Seconds to delay the OS response.")
        row += 1
        self._create_input_field(parent_frame, "Temp Path (--tmp-path):", row, "tmp_path_entry", width=60,
                                 help_text="Set the absolute path of web server's temp directory.")
        row += 1
        self._create_input_field(parent_frame, "Web Root (--web-root):", row, "web_root_entry", width=60,
                                 help_text="Set the web server document root directory (e.g. '/var/www').")
        row += 1
        self._create_input_field(parent_frame, "Alter Shell (--alter-shell):", row, "alter_shell_entry", width=20,
                                 help_text="Use an alternative os-shell (e.g. 'Python').")
        row += 1
        self._create_input_field(parent_frame, "OS Command (--os-cmd):", row, "os_cmd_entry", width=60,
                                 help_text="Execute a single operating system command.")
        row += 1
        self._create_input_field(parent_frame, "OS (--os):", row, "os_entry", width=20,
                                 help_text="Force back-end operating system (e.g. 'Windows' or 'Unix').")
        row += 1
        self._create_input_field(parent_frame, "Tamper Script (--tamper):", row, "tamper_entry", width=60,
                                 help_text="Use given script(s) for tampering injection data.")
        row += 1
        self._create_input_field(parent_frame, "MSF Path (--msf-path):", row, "msf_path_entry", width=60,
                                 help_text="Set a local path where metasploit is installed.")

    def _create_detection_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Level (--level):", row, "level_entry", width=10,
                                 help_text="Level of tests to perform (1-3, Default: 1).")
        row += 1
        self._create_input_field(parent_frame, "Skip Calculation (--skip-calc):", row, None, is_checkbox=True, var_name="skip_calc_var",
                                 help_text="Skip the mathematic calculation during the detection phase.")
        row += 1
        self._create_input_field(parent_frame, "Skip Empty (--skip-empty):", row, None, is_checkbox=True, var_name="skip_empty_var",
                                 help_text="Skip testing the parameter(s) with empty value(s).")
        row += 1
        self._create_input_field(parent_frame, "Failed Tries (--failed-tries):", row, "failed_tries_entry", width=10,
                                 help_text="Set a number of failed injection tries, in file-based technique.")
        row += 1
        self._create_input_field(parent_frame, "Smart (--smart):", row, None, is_checkbox=True, var_name="smart_var",
                                 help_text="Perform thorough tests only if positive heuristic(s).")

    def _create_misc_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Ignore Dependencies (--ignore-dependencies):", row, None, is_checkbox=True, var_name="ignore_dependencies_var",
                                 help_text="Ignore all required third-party library dependencies.")
        row += 1
        self._create_input_field(parent_frame, "List Tampers (--list-tampers):", row, None, is_checkbox=True, var_name="list_tampers_var",
                                 help_text="Display list of available tamper scripts.")
        row += 1
        self._create_input_field(parent_frame, "Alert (--alert):", row, "alert_entry", width=60,
                                 help_text="Run host OS command(s) when injection point is found.")
        row += 1
        self._create_input_field(parent_frame, "No Logging (--no-logging):", row, None, is_checkbox=True, var_name="no_logging_var",
                                 help_text="Disable logging to a file.")
        row += 1
        self._create_input_field(parent_frame, "Purge (--purge):", row, None, is_checkbox=True, var_name="purge_var",
                                 help_text="Safely remove all content from commix data directory.")
        row += 1
        self._create_input_field(parent_frame, "Skip WAF (--skip-waf):", row, None, is_checkbox=True, var_name="skip_waf_var",
                                 help_text="Skip heuristic detection of WAF/IPS protection.")
        row += 1
        self._create_input_field(parent_frame, "Mobile (--mobile):", row, None, is_checkbox=True, var_name="mobile_var",
                                 help_text="Imitate smartphone through HTTP User-Agent header.")
        row += 1
        self._create_input_field(parent_frame, "Offline (--offline):", row, None, is_checkbox=True, var_name="offline_var",
                                 help_text="Work in offline mode.")
        row += 1
        self._create_input_field(parent_frame, "Wizard (--wizard):", row, None, is_checkbox=True, var_name="wizard_var",
                                 help_text="Simple wizard interface for beginner users.")
        row += 1
        self._create_input_field(parent_frame, "Disable Coloring (--disable-coloring):", row, None, is_checkbox=True, var_name="disable_coloring_var",
                                 help_text="Disable console output coloring.")

    def run_commix(self):
        if self.commix_process and self.commix_process.poll() is None:
            messagebox.showwarning("Commix Running", "Commix is already running. Please wait for it to finish or close the application.")
            return

        self.clear_output()
        self.status_bar.config(text="Commix is running...")
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, "Starting Commix...\n")
        self.output_text.config(state=tk.DISABLED)

        command = [sys.executable, "commix.py"]

        def add_arg(arg_name, entry_widget):
            value = entry_widget.get().strip()
            if value:
                command.append(arg_name)
                command.append(value)

        def add_checkbox_arg(arg_name, var_widget):
            if var_widget.get():
                command.append(arg_name)

        def add_dropdown_arg(arg_name, var_widget):
            value = var_widget.get().strip()
            if value:
                command.append(arg_name)
                command.append(value)

        # General Options
        add_arg("-v", self.verbose_entry)
        add_arg("--output-dir", self.output_dir_entry)
        add_arg("-s", self.session_file_entry)
        add_checkbox_arg("--flush-session", self.flush_session_var)
        add_checkbox_arg("--ignore-session", self.ignore_session_var)
        add_arg("-t", self.traffic_file_entry)
        add_arg("--time-limit", self.time_limit_entry)
        add_checkbox_arg("--batch", self.batch_var)
        add_checkbox_arg("--skip-heuristics", self.skip_heuristics_var)
        add_arg("--codec", self.codec_entry)
        add_arg("--charset", self.charset_entry)
        add_checkbox_arg("--check-internet", self.check_internet_var)
        add_arg("--answers", self.answers_entry)

        # Target Options
        add_arg("-u", self.url_entry)
        add_checkbox_arg("--url-reload", self.url_reload_var)
        add_arg("-l", self.logfile_entry)
        add_arg("-m", self.bulkfile_entry)
        add_arg("-r", self.requestfile_entry)
        add_arg("--crawl", self.crawldepth_entry)
        add_arg("--crawl-exclude", self.crawl_exclude_entry)
        add_arg("-x", self.sitemap_url_entry)
        add_arg("--method", self.method_entry)

        # Request Options
        add_arg("--data", self.data_entry)
        add_arg("--host", self.host_entry)
        add_arg("--referer", self.referer_entry)
        add_arg("--user-agent", self.user_agent_entry)
        add_checkbox_arg("--random-agent", self.random_agent_var)
        add_arg("--param-del", self.param_del_entry)
        add_arg("--cookie", self.cookie_entry)
        add_arg("--cookie-del", self.cookie_del_entry)
        add_arg("--header", self.header_entry)
        add_arg("--headers", self.headers_entry)
        add_arg("--proxy", self.proxy_entry)
        add_checkbox_arg("--tor", self.tor_var)
        add_arg("--tor-port", self.tor_port_entry)
        add_checkbox_arg("--tor-check", self.tor_check_var)
        add_arg("--auth-url", self.auth_url_entry)
        add_arg("--auth-data", self.auth_data_entry)
        add_dropdown_arg("--auth-type", self.auth_type_var)
        add_arg("--auth-cred", self.auth_cred_entry)
        add_arg("--abort-code", self.abort_code_entry)
        add_arg("--ignore-code", self.ignore_code_entry)
        add_checkbox_arg("--force-ssl", self.force_ssl_var)
        add_checkbox_arg("--ignore-proxy", self.ignore_proxy_var)
        add_checkbox_arg("--ignore-redirects", self.ignore_redirects_var)
        add_arg("--timeout", self.timeout_entry)
        add_arg("--retries", self.retries_entry)
        add_checkbox_arg("--drop-set-cookie", self.drop_set_cookie_var)

        # Enumeration Options
        add_checkbox_arg("--all", self.enum_all_var)
        add_checkbox_arg("--current-user", self.current_user_var)
        add_checkbox_arg("--hostname", self.hostname_var)
        add_checkbox_arg("--is-root", self.is_root_var)
        add_checkbox_arg("--is-admin", self.is_admin_var)
        add_checkbox_arg("--sys-info", self.sys_info_var)
        add_checkbox_arg("--users", self.users_var)
        add_checkbox_arg("--passwords", self.passwords_var)
        add_checkbox_arg("--privileges", self.privileges_var)
        add_checkbox_arg("--ps-version", self.ps_version_var)

        # File Access Options
        add_arg("--file-read", self.file_read_entry)
        add_arg("--file-write", self.file_write_entry)
        add_arg("--file-upload", self.file_upload_entry)
        add_arg("--file-dest", self.file_dest_entry)

        # Modules Options
        add_checkbox_arg("--shellshock", self.shellshock_var)

        # Injection Options
        add_arg("-p", self.test_parameter_entry)
        add_arg("--skip", self.skip_parameter_entry)
        add_arg("--suffix", self.suffix_entry)
        add_arg("--prefix", self.prefix_entry)
        add_arg("--technique", self.technique_entry)
        add_arg("--skip-technique", self.skip_technique_entry)
        add_arg("--maxlen", self.maxlen_entry)
        add_arg("--delay", self.delay_entry)
        add_arg("--time-sec", self.timesec_entry)
        add_arg("--tmp-path", self.tmp_path_entry)
        add_arg("--web-root", self.web_root_entry)
        add_arg("--alter-shell", self.alter_shell_entry)
        add_arg("--os-cmd", self.os_cmd_entry)
        add_arg("--os", self.os_entry)
        add_arg("--tamper", self.tamper_entry)
        add_arg("--msf-path", self.msf_path_entry)

        # Detection Options
        add_arg("--level", self.level_entry)
        add_checkbox_arg("--skip-calc", self.skip_calc_var)
        add_checkbox_arg("--skip-empty", self.skip_empty_var)
        add_arg("--failed-tries", self.failed_tries_entry)
        add_checkbox_arg("--smart", self.smart_var)

        # Miscellaneous Options
        add_checkbox_arg("--ignore-dependencies", self.ignore_dependencies_var)
        add_checkbox_arg("--list-tampers", self.list_tampers_var)
        add_arg("--alert", self.alert_entry)
        add_checkbox_arg("--no-logging", self.no_logging_var)
        add_checkbox_arg("--purge", self.purge_var)
        add_checkbox_arg("--skip-waf", self.skip_waf_var)
        add_checkbox_arg("--mobile", self.mobile_var)
        add_checkbox_arg("--offline", self.offline_var)
        add_checkbox_arg("--wizard", self.wizard_var)
        add_checkbox_arg("--disable-coloring", self.disable_coloring_var)

        # Additional Arguments
        additional_args = self.additional_args_text.get("1.0", tk.END).strip()
        if additional_args:
            command.extend(additional_args.split())

        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, f"Executing command: {' '.join(command)}\n\n")
        self.output_text.config(state=tk.DISABLED)

        self.commix_thread = threading.Thread(target=self._run_commix_thread, args=(command,))
        self.commix_thread.daemon = True
        self.commix_thread.start()

    def _run_commix_thread(self, command):
        try:
            self.commix_process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                cwd=os.path.dirname(os.path.abspath("commix.py"))
            )

            def read_output(pipe, output_queue):
                for line in iter(pipe.readline, ''):
                    output_queue.put(line)
                pipe.close()

            stdout_thread = threading.Thread(target=read_output, args=(self.commix_process.stdout, self.output_queue))
            stderr_thread = threading.Thread(target=read_output, args=(self.commix_process.stderr, self.output_queue))
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()

            self.commix_process.wait()
            return_code = self.commix_process.returncode
            self.output_queue.put(f"\nCommix finished with exit code: {return_code}\n")
            self.output_queue.put(f"STATUS: {'Completed' if return_code == 0 else 'Failed'}\n")

        except FileNotFoundError:
            self.output_queue.put("Error: commix.py not found. Make sure it's in the same directory as commix_gui.py.\n")
            self.output_queue.put("STATUS: Error\n")
        except Exception as e:
            self.output_queue.put(f"An error occurred: {e}\n")
            self.output_queue.put("STATUS: Error\n")
        finally:
            self.master.after(0, lambda: setattr(self, 'commix_process', None))
            self.master.after(0, lambda: self.status_bar.config(text="Ready"))
            self.master.after(0, self.hide_interactive_input)

    def process_queue(self):
        prompt_detected = False
        while not self.output_queue.empty():
            try:
                line = self.output_queue.get_nowait()
                self.output_text.config(state=tk.NORMAL)
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
                self.output_text.config(state=tk.DISABLED)

                if re.search(r"\[[YyNnQq\/]+\]", line) or re.search(r"\[\d+\/\d+\]", line):
                    prompt_detected = True

            except queue.Empty:
                pass
        
        if prompt_detected:
            self.show_interactive_input()
            self.status_bar.config(text="Waiting for user input...")
        else:
            self.hide_interactive_input()
            if self.commix_process and self.commix_process.poll() is None:
                self.status_bar.config(text="Commix is running...")
            else:
                self.status_bar.config(text="Ready")

        self.master.after(100, self.process_queue)

    def show_interactive_input(self):
        self.interactive_input_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        self.interactive_input_entry.focus_set()

    def hide_interactive_input(self):
        self.interactive_input_frame.pack_forget()
        self.interactive_input_entry.delete(0, tk.END)

    def send_input_to_commix(self):
        user_input = self.interactive_input_entry.get().strip()
        if self.commix_process and self.commix_process.stdin:
            try:
                self.commix_process.stdin.write(user_input + '\n')
                self.commix_process.stdin.flush()
                self.output_text.config(state=tk.NORMAL)
                self.output_text.insert(tk.END, f"> {user_input}\n")
                self.output_text.config(state=tk.DISABLED)
                self.hide_interactive_input()
                self.status_bar.config(text="Commix is running...")
                self.master.after(10, self.process_queue)
            except Exception as e:
                self.output_queue.put(f"Error sending input to Commix: {e}\n")
                self.hide_interactive_input()
                self.status_bar.config(text="Error sending input")
        else:
            messagebox.showerror("Error", "Commix process is not running or stdin is not available.")
            self.hide_interactive_input()

    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.status_bar.config(text="Ready")
        self.clear_search_highlight()
        self.hide_interactive_input()

    def search_output(self, event=None):
        search_term = self.search_entry.get().strip()
        self.clear_search_highlight()

        if not search_term:
            self.search_start_index = "1.0"
            return

        self.output_text.config(state=tk.NORMAL)
        
        if self.search_start_index == "1.0" or not self.output_text.search(search_term, self.search_start_index, tk.END, nocase=1):
            self.search_start_index = "1.0"

        idx = self.output_text.search(search_term, self.search_start_index, tk.END, nocase=1)
        if idx:
            end_idx = f"{idx}+{len(search_term)}c"
            self.output_text.tag_add("highlight", idx, end_idx)
            self.output_text.see(idx)
            self.search_start_index = end_idx
        else:
            messagebox.showinfo("Search", f"No more occurrences of '{search_term}' found.")
            self.search_start_index = "1.0"

        self.output_text.config(state=tk.DISABLED)

    def clear_search_highlight(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.tag_remove("highlight", "1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.search_start_index = "1.0"

    def on_closing(self):
        if self.commix_process and self.commix_process.poll() is None:
            if messagebox.askokcancel("Quit", "Commix is still running. Do you want to terminate it and quit?"):
                self.commix_process.terminate()
                self.master.destroy()
        else:
            self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CommixGUI(root)
    root.mainloop()