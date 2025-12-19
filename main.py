import tkinter as tk
from tkinter import messagebox, ttk
import hashlib
import json
import random
import string
import datetime
import os
import sys
import base64

# ==========================================
# 工具类：路径与资源
# ==========================================
class AppUtils:
    @staticmethod
    def get_base_path():
        if hasattr(sys, '_MEIPASS'):
            return sys._MEIPASS
        return os.path.dirname(os.path.abspath(__file__))

    @staticmethod
    def get_resource_path(relative_path):
        return os.path.join(AppUtils.get_base_path(), relative_path)

    @staticmethod
    def get_data_file_path():
        app_data_dir = os.getenv('APPDATA')
        if not app_data_dir:
             app_data_dir = os.path.expanduser("~")
        my_app_folder = os.path.join(app_data_dir, "MySecurePasswordApp")
        if not os.path.exists(my_app_folder):
            try:
                os.makedirs(my_app_folder)
            except Exception:
                return "data.json"
        return os.path.join(my_app_folder, 'data.json')

    @staticmethod
    def center_window(window, width, height):
        """让窗口在屏幕居中显示"""
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = int((screen_width - width) / 2)
        y = int((screen_height - height) / 2)
        window.geometry(f'{width}x{height}+{x}+{y}')

# ==========================================
# 加密引擎 (保持不变)
# ==========================================
class SimpleCrypt:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    @staticmethod
    def encrypt_string(plaintext: str, key: bytes) -> str:
        try:
            if not plaintext: return ""
            iv = os.urandom(16)
            keystream_seed = key + iv
            keystream = hashlib.sha256(keystream_seed).digest()
            text_bytes = plaintext.encode('utf-8')
            while len(keystream) < len(text_bytes):
                keystream += hashlib.sha256(keystream).digest()
            encrypted_bytes = bytearray()
            for i in range(len(text_bytes)):
                encrypted_bytes.append(text_bytes[i] ^ keystream[i])
            return base64.b64encode(iv + encrypted_bytes).decode('utf-8')
        except Exception:
            return ""

    @staticmethod
    def decrypt_string(ciphertext_b64: str, key: bytes) -> str:
        try:
            if not ciphertext_b64: return ""
            data = base64.b64decode(ciphertext_b64)
            if len(data) < 17: return ""
            iv = data[:16]
            encrypted_bytes = data[16:]
            keystream_seed = key + iv
            keystream = hashlib.sha256(keystream_seed).digest()
            while len(keystream) < len(encrypted_bytes):
                keystream += hashlib.sha256(keystream).digest()
            decrypted_bytes = bytearray()
            for i in range(len(encrypted_bytes)):
                decrypted_bytes.append(encrypted_bytes[i] ^ keystream[i])
            return decrypted_bytes.decode('utf-8')
        except Exception:
            return "Error"

# ==========================================
# 业务逻辑层
# ==========================================
class PasswordManagerLogic:
    def __init__(self):
        self.file_path = AppUtils.get_data_file_path()
        self.session_key = None 
        self.raw_data = self._load_raw_data()
        self.decrypted_cache = [] 

    def _load_raw_data(self):
        if not os.path.exists(self.file_path):
            return {"salt": None, "verify_hash": None, "records": []}
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {"salt": None, "verify_hash": None, "records": []}

    def save_data(self):
        try:
            with open(self.file_path, 'w', encoding='utf-8') as f:
                json.dump(self.raw_data, f, ensure_ascii=False, indent=4)
        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {str(e)}")

    def is_first_run(self):
        return self.raw_data.get("salt") is None

    def check_password_strength(self, password):
        if len(password) < 8: return False, "密码长度必须至少 8 位"
        if not any(c.isupper() for c in password): return False, "需包含大写字母"
        if not any(c.islower() for c in password): return False, "需包含小写字母"
        if not any(c.isdigit() for c in password): return False, "需包含数字"
        if not any(c in string.punctuation for c in password): return False, "需包含符号"
        return True, "合格"

    def register_master_password(self, password):
        salt = os.urandom(16)
        key = SimpleCrypt.derive_key(password, salt)
        verify_token = SimpleCrypt.encrypt_string("CHECK_VALID", key)
        self.raw_data["salt"] = base64.b64encode(salt).decode()
        self.raw_data["verify_hash"] = verify_token
        self.raw_data["records"] = []
        self.session_key = key
        self.save_data()

    def login(self, password):
        try:
            salt_b64 = self.raw_data.get("salt")
            verify_token = self.raw_data.get("verify_hash")
            if not salt_b64 or not verify_token: return False
            salt = base64.b64decode(salt_b64)
            derived_key = SimpleCrypt.derive_key(password, salt)
            if SimpleCrypt.decrypt_string(verify_token, derived_key) == "CHECK_VALID":
                self.session_key = derived_key
                self.refresh_decrypted_cache()
                return True
            return False
        except Exception:
            return False

    def add_record(self, username, password, remark=""):
        if not self.session_key: return
        enc_user = SimpleCrypt.encrypt_string(username, self.session_key)
        enc_pass = SimpleCrypt.encrypt_string(password, self.session_key)
        enc_remark = SimpleCrypt.encrypt_string(remark, self.session_key)
        
        record = {
            "id": self._generate_id(),
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "u_enc": enc_user, "p_enc": enc_pass, "r_enc": enc_remark
        }
        self.raw_data["records"].insert(0, record)
        self.save_data()
        self.refresh_decrypted_cache()

    def update_record(self, record_id, new_user, new_pass, new_remark):
        if not self.session_key: return False
        found = False
        for record in self.raw_data["records"]:
            if record.get("id") == record_id:
                record["u_enc"] = SimpleCrypt.encrypt_string(new_user, self.session_key)
                record["p_enc"] = SimpleCrypt.encrypt_string(new_pass, self.session_key)
                record["r_enc"] = SimpleCrypt.encrypt_string(new_remark, self.session_key)
                found = True
                break
        if found:
            self.save_data()
            self.refresh_decrypted_cache()
            return True
        return False

    def delete_record(self, record_id):
        self.raw_data["records"] = [r for r in self.raw_data["records"] if r.get("id") != record_id]
        self.save_data()
        self.refresh_decrypted_cache()

    def _generate_id(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    def refresh_decrypted_cache(self):
        self.decrypted_cache = []
        if not self.session_key: return
        for r in self.raw_data["records"]:
            try:
                self.decrypted_cache.append({
                    "id": r.get("id", ""),
                    "created_at": r["created_at"],
                    "username": SimpleCrypt.decrypt_string(r["u_enc"], self.session_key),
                    "password": SimpleCrypt.decrypt_string(r["p_enc"], self.session_key),
                    "remark": SimpleCrypt.decrypt_string(r["r_enc"], self.session_key),
                })
            except:
                continue

    def search_records(self, query):
        if not query: return self.decrypted_cache
        query = query.lower()
        return [r for r in self.decrypted_cache if query in r["remark"].lower() or query in r["username"].lower()]

    @staticmethod
    def generate_random_username():
        return ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 12)))

    @staticmethod
    def generate_strong_password():
        length = 16
        pool = [string.ascii_uppercase, string.ascii_lowercase, string.digits, "!@#$%^&*()_+-=[]{}|;:,.<>?"]
        chars = [random.choice(p) for p in pool]
        chars += random.choices(''.join(pool), k=length - 4)
        random.shuffle(chars)
        return ''.join(chars)

# ==========================================
# 界面层 (UI) - 深度美化版
# ==========================================
class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("安全金库 Pro")
        self.width = 850
        self.height = 700
        AppUtils.center_window(self, self.width, self.height)
        self.resizable(False, False)
        
        # 图标
        icon_path = AppUtils.get_resource_path('newlogo.ico')
        if os.path.exists(icon_path):
            self.iconbitmap(icon_path)
        
        # === 全局样式美化配置 ===
        self.configure_styles()
        
        self.logic = PasswordManagerLogic()
        self.is_password_visible = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="就绪") # 底部状态栏变量

        if self.logic.is_first_run():
            self.show_setup_master_password_ui()
        else:
            self.show_login_ui()

    def configure_styles(self):
        """配置 TTK 样式，打造现代扁平化外观"""
        style = ttk.Style()
        style.theme_use('clam') # 使用 clam 主题作为基础，比 default 好看

        # 定义颜色
        BG_COLOR = "#F4F6F9" # 浅灰背景
        PRIMARY_COLOR = "#0078D7" # 微软蓝
        SUCCESS_COLOR = "#28a745" # 成功绿
        INFO_COLOR = "#17a2b8"    # 信息蓝
        
        self.configure(bg=BG_COLOR) # 窗口背景

        # 字体配置
        BASE_FONT = ("Segoe UI", 10)
        BOLD_FONT = ("Segoe UI", 10, "bold")
        HEADER_FONT = ("Segoe UI", 12, "bold")

        # 1. 标签
        style.configure("TLabel", background=BG_COLOR, font=BASE_FONT)
        style.configure("Header.TLabel", background=BG_COLOR, font=HEADER_FONT, foreground="#333")

        # 2. 按钮 (扁平化)
        style.configure("TButton", font=BASE_FONT, padding=6, borderwidth=1)
        style.map("TButton", background=[("active", "#E1E1E1")]) # 鼠标悬停变色

        # 特殊按钮样式
        style.configure("Primary.TButton", background=PRIMARY_COLOR, foreground="white", borderwidth=0)
        style.map("Primary.TButton", background=[("active", "#005a9e")]) # 深蓝悬停

        style.configure("Success.TButton", background=SUCCESS_COLOR, foreground="white", borderwidth=0)
        style.map("Success.TButton", background=[("active", "#218838")]) 

        style.configure("Info.TButton", background=INFO_COLOR, foreground="white", borderwidth=0)
        style.map("Info.TButton", background=[("active", "#138496")])

        # 3. 输入框
        style.configure("TEntry", padding=5, font=BASE_FONT)

        # 4. 列表 (Treeview) - 最重要的美化部分
        style.configure("Treeview", 
                        background="white",
                        foreground="black", 
                        rowheight=28, # 增加行高，不拥挤
                        fieldbackground="white",
                        font=BASE_FONT)
        style.configure("Treeview.Heading", font=BOLD_FONT, background="#E9ECEF", foreground="#495057")
        style.map("Treeview", background=[('selected', PRIMARY_COLOR)])

        # 5. LabelFrame
        style.configure("TLabelframe", background=BG_COLOR)
        style.configure("TLabelframe.Label", background=BG_COLOR, font=BOLD_FONT, foreground="#0078D7")

        # 6. Checkbutton
        style.configure("TCheckbutton", background=BG_COLOR, font=BASE_FONT)

    def set_status(self, text, is_error=False):
        """更新底部状态栏"""
        self.status_var.set(text)
        if is_error:
            self.status_bar.config(fg="red")
        else:
            self.status_bar.config(fg="#333")
        # 3秒后自动复位
        self.after(3000, lambda: self.status_bar.config(fg="#333"))

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    # --- 登录注册界面 (美化版) ---
    def show_setup_master_password_ui(self):
        self.clear_window()
        self._build_auth_ui("🛡️ 初始化金库", "立即初始化", self.handle_setup_password, True)

    def show_login_ui(self):
        self.clear_window()
        self._build_auth_ui("🔐 解密金库", "解锁进入", self.handle_login, False)

    def _build_auth_ui(self, title, btn_text, command, is_setup):
        # 使用 Frame 居中布局
        center_frame = tk.Frame(self, bg="white", padx=40, pady=40, relief="raised", bd=1)
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(center_frame, text=title, font=("Segoe UI", 18, "bold"), background="white").pack(pady=(0, 20))

        if is_setup:
            ttk.Label(center_frame, text="密码要求：长度>8，含大小写、数字及符号", 
                     foreground="#666", background="white", font=("Segoe UI", 9)).pack(pady=(0, 15))

        # 密码输入容器
        input_container = tk.Frame(center_frame, bg="white", highlightbackground="#ddd", highlightthickness=1)
        input_container.pack(pady=10, fill="x")

        self.entry_pwd = tk.Entry(input_container, show="*", font=("Segoe UI", 12), bd=0, width=22)
        self.entry_pwd.pack(side="left", padx=10, pady=8)
        self.entry_pwd.bind('<Return>', lambda event: command())

        # 眼睛图标 (使用 Unicode)
        self.var_auth_show_pass = tk.BooleanVar(value=False)
        def toggle():
            self.entry_pwd.config(show="" if self.var_auth_show_pass.get() else "*")
        
        # 使用 Checkbutton 稍微有点丑，这里用文字按钮模拟更好
        chk = tk.Checkbutton(input_container, text="👁️", variable=self.var_auth_show_pass, 
                             command=toggle, bg="white", activebackground="white", bd=0, cursor="hand2")
        chk.pack(side="right", padx=5)

        ttk.Button(center_frame, text=btn_text, command=command, style="Primary.TButton", width=25).pack(pady=20)
        
        ttk.Label(center_frame, text="基于 Python 标准库的安全加密", background="white", foreground="#aaa", font=("Segoe UI", 8)).pack(side="bottom")

    def handle_setup_password(self):
        pwd = self.entry_pwd.get()
        valid, msg = self.logic.check_password_strength(pwd)
        if not valid:
            messagebox.showwarning("强度不足", msg)
            return
        self.logic.register_master_password(pwd)
        self.show_main_ui()

    def handle_login(self):
        if self.logic.login(self.entry_pwd.get()):
            self.show_main_ui()
        else:
            self.entry_pwd.delete(0, 'end')
            # 震动效果(模拟)或变红
            self.entry_pwd.config(bg="#ffe6e6")
            self.after(200, lambda: self.entry_pwd.config(bg="white"))
            messagebox.showerror("错误", "密码错误，无法解密数据")

    # --- 主界面 (Grid 布局重构，完美对齐) ---
    def show_main_ui(self):
        self.clear_window()
        self.configure(bg="#F4F6F9")

        # 1. 顶部：输入录入区 (使用 LabelFrame 分组)
        input_frame = ttk.LabelFrame(self, text=" 📝 新增 / 录入 ", padding=(20, 15))
        input_frame.pack(fill="x", padx=20, pady=15)

        # 使用 Grid 布局让标签和输入框严格对齐
        input_frame.columnconfigure(1, weight=1) # 让输入框自动拉伸

        # 第一行：备注
        ttk.Label(input_frame, text="备注名称:").grid(row=0, column=0, sticky="e", padx=(0, 10), pady=8)
        self.var_input_remark = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.var_input_remark).grid(row=0, column=1, sticky="ew", padx=(0, 10))
        ttk.Label(input_frame, text="(如: 淘宝主号)", foreground="#888").grid(row=0, column=2, sticky="w")

        # 第二行：用户名
        ttk.Label(input_frame, text="账号/用户:").grid(row=1, column=0, sticky="e", padx=(0, 10), pady=8)
        self.var_input_user = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.var_input_user).grid(row=1, column=1, columnspan=2, sticky="ew")

        # 第三行：密码
        ttk.Label(input_frame, text="安全密码:").grid(row=2, column=0, sticky="e", padx=(0, 10), pady=8)
        self.var_input_pass = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.var_input_pass).grid(row=2, column=1, columnspan=2, sticky="ew")

        # 第四行：按钮组 (放在一个新的 Frame 里方便居中或对齐)
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=3, column=0, columnspan=3, pady=(15, 0), sticky="ew")

        # 按钮使用特定样式
        ttk.Button(btn_frame, text="🎲 随机生成 (不保存)", style="Info.TButton", 
                   command=self.action_fill_random).pack(side="left", padx=(0, 10))
        
        ttk.Button(btn_frame, text="💾 保存录入", style="Success.TButton", 
                   command=self.action_save_manual).pack(side="left")
        
        ttk.Button(btn_frame, text="清空", command=self.action_clear_inputs).pack(side="right")

        # 2. 中间：工具条 (搜索 + 显示密码)
        tool_frame = ttk.Frame(self)
        tool_frame.pack(fill="x", padx=20, pady=(0, 10))

        ttk.Label(tool_frame, text="🔍").pack(side="left")
        self.var_search = tk.StringVar()
        self.var_search.trace("w", lambda *args: self.refresh_list(self.var_search.get()))
        
        search_entry = ttk.Entry(tool_frame, textvariable=self.var_search, width=25)
        search_entry.pack(side="left", padx=5)
        
        ttk.Label(tool_frame, text="(输入关键词过滤)", foreground="#888", font=("Segoe UI", 9)).pack(side="left")

        ttk.Checkbutton(tool_frame, text="显示明文密码", variable=self.is_password_visible, 
                       command=lambda: self.refresh_list(self.var_search.get())).pack(side="right")

        # 3. 底部：列表区
        list_frame = ttk.Frame(self) # 外框用于包裹滚动条
        list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        cols = ("id", "time", "remark", "user", "pass")
        self.tree = ttk.Treeview(list_frame, columns=cols, show="headings", selectmode="browse")
        
        # 滚动条美化
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        
        self.tree.heading("time", text="最后修改时间")
        self.tree.heading("remark", text="备注 / 用途")
        self.tree.heading("user", text="用户名 / 账号")
        self.tree.heading("pass", text="密码")
        
        self.tree.column("id", width=0, stretch=False)
        self.tree.column("time", width=140, anchor="center")
        self.tree.column("remark", width=150, anchor="w")
        self.tree.column("user", width=180, anchor="w")
        self.tree.column("pass", width=180, anchor="w")

        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # 4. 底部状态栏
        self.status_bar = tk.Label(self, textvariable=self.status_var, bd=1, relief="sunken", anchor="w", 
                                  bg="#e9ecef", fg="#333", font=("Segoe UI", 9), padx=10, pady=2)
        self.status_bar.pack(side="bottom", fill="x")

        # 绑定事件
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.on_double_click_item)
        self.create_context_menu()
        
        self.refresh_list()
        self.set_status("就绪 - 双击列表项可编辑，右键可复制")

    # === 操作逻辑 (逻辑保持稳定，增加状态栏反馈) ===
    def action_fill_random(self):
        self.var_input_user.set(self.logic.generate_random_username())
        self.var_input_pass.set(self.logic.generate_strong_password())
        self.set_status("已生成随机账号密码，请记得点击保存！")

    def action_save_manual(self):
        u = self.var_input_user.get().strip()
        p = self.var_input_pass.get().strip()
        r = self.var_input_remark.get().strip()
        if not u or not p:
            messagebox.showwarning("提示", "用户名和密码不能为空！")
            return
        self.logic.add_record(u, p, r)
        self.refresh_list()
        self.action_clear_inputs()
        self.set_status("✅ 保存成功！", is_error=False)

    def action_clear_inputs(self):
        self.var_input_user.set("")
        self.var_input_pass.set("")
        self.var_input_remark.set("")
        self.set_status("已清空输入框")

    def on_double_click_item(self, event):
        item = self.tree.identify_row(event.y)
        if not item: return
        self.show_edit_dialog(item)

    def show_edit_dialog(self, item_id_tree):
        vals = self.tree.item(item_id_tree)['values']
        record_id = vals[0]
        real_record = next((r for r in self.logic.decrypted_cache if r["id"] == record_id), None)
        if not real_record: return
        
        # 弹窗美化
        edit_win = tk.Toplevel(self)
        edit_win.title("编辑记录")
        edit_win.geometry("450x320")
        edit_win.configure(bg="#F4F6F9")
        AppUtils.center_window(edit_win, 450, 320)
        edit_win.transient(self)
        edit_win.grab_set()

        pad_opts = {'padx': 20, 'pady': 10}
        
        ttk.Label(edit_win, text="备注:", background="#F4F6F9").pack(anchor="w", padx=20, pady=(15, 0))
        v_rem = tk.StringVar(value=real_record["remark"])
        ttk.Entry(edit_win, textvariable=v_rem, width=50).pack(**pad_opts)

        ttk.Label(edit_win, text="用户名:", background="#F4F6F9").pack(anchor="w", padx=20)
        v_user = tk.StringVar(value=real_record["username"])
        ttk.Entry(edit_win, textvariable=v_user, width=50).pack(**pad_opts)

        ttk.Label(edit_win, text="密码:", background="#F4F6F9").pack(anchor="w", padx=20)
        v_pass = tk.StringVar(value=real_record["password"])
        ttk.Entry(edit_win, textvariable=v_pass, width=50).pack(**pad_opts)

        def save_changes():
            new_r = v_rem.get().strip()
            new_u = v_user.get().strip()
            new_p = v_pass.get().strip()
            if not new_u or not new_p:
                messagebox.showwarning("警告", "账号密码不能为空", parent=edit_win)
                return
            if self.logic.update_record(record_id, new_u, new_p, new_r):
                self.refresh_list(self.var_search.get())
                self.set_status("✅ 修改已保存")
                edit_win.destroy()
            else:
                messagebox.showerror("错误", "更新失败")
        
        ttk.Button(edit_win, text="💾 保存修改", command=save_changes, style="Primary.TButton", width=20).pack(pady=20)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self, tearoff=0, bg="white", fg="black")
        self.context_menu.add_command(label="✏️ 编辑此条", command=self.edit_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📄 复制账号", command=self.copy_selected_user)
        self.context_menu.add_command(label="🔑 复制密码", command=self.copy_selected_pass)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🗑️ 删除", command=self.delete_selected, foreground="red")

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def refresh_list(self, query=""):
        for item in self.tree.get_children():
            self.tree.delete(item)
        records = self.logic.search_records(query)
        show_pass = self.is_password_visible.get()
        for r in records:
            display_pass = r["password"] if show_pass else "••••••••" # 使用圆点更美观
            self.tree.insert("", "end", values=(r["id"], r["created_at"], r["remark"], r["username"], display_pass))

    def copy_to_clipboard(self, text):
        if not text: return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        self.set_status("📋 已复制到剪贴板 (60秒后自动清除)")
        self.after(60000, lambda: self.clipboard_clear())

    def edit_selected(self):
        sel = self.tree.selection()
        if sel: self.show_edit_dialog(sel[0])

    def copy_selected_user(self):
        sel = self.tree.selection()
        if sel:
            item_id = self.tree.item(sel[0])['values'][0]
            real = next((r for r in self.logic.decrypted_cache if r["id"] == item_id), None)
            if real: self.copy_to_clipboard(real["username"])

    def copy_selected_pass(self):
        sel = self.tree.selection()
        if sel:
            item_id = self.tree.item(sel[0])['values'][0]
            real = next((r for r in self.logic.decrypted_cache if r["id"] == item_id), None)
            if real: self.copy_to_clipboard(real["password"])

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel: return
        if messagebox.askyesno("确认删除", "确定要永久删除这条记录吗？"):
            item_id = self.tree.item(sel[0])['values'][0]
            self.logic.delete_record(item_id)
            self.refresh_list(self.var_search.get())
            self.set_status("🗑️ 记录已删除")

if __name__ == "__main__":
    try:
        app = Application()
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Crash", f"Error: {e}")