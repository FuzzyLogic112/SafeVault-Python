
# 🛡️ SafeVault - 本地安全密码管理器
<img width="1276" height="1099" alt="image" src="https://github.com/user-attachments/assets/d7054225-e216-4757-a555-c7978b5d668f" />


> 一个基于 Python Tkinter 构建的现代化、零依赖、高安全性的本地密码管理工具。

## 📖 项目简介

**SafeVault** 是一个为重视隐私的用户设计的单文件密码管理软件。它不依赖任何云服务，所有数据均经过高强度加密后存储在本地。

项目完全使用 Python 标准库编写（无需 `pip install` 任何第三方依赖库即可运行源码），结合现代化的 Flat UI 设计，提供了流畅的用户体验。
<img width="638" height="543" alt="image" src="https://github.com/user-attachments/assets/346e0ded-5eda-4c16-a9fa-894652b71fdb" />

## ✨ 核心功能

* **🛡️ 军工级安全性**：
* **零知识证明**：主密码经过 `PBKDF2-HMAC-SHA256` 10万次迭代哈希处理，程序不保存明文主密码。
* **强加密存储**：数据采用自定义的 XOR 流加密算法（基于 Session Key 派生），即使数据库文件被盗也无法破解。
* **内存安全**：解密密钥仅在运行时存在于内存中，关闭即焚。


* **🎨 现代化 UI 设计**：
* 基于 `ttk.Style` 的扁平化界面。
* 支持高分屏显示，自动居中。
* 底部实时状态栏反馈。


* **⚡ 便捷操作**：
* **随机生成器**：一键生成包含大小写、数字、符号的 16 位强密码。
* **右键菜单**：支持右键快速复制账号/密码、编辑或删除。
* **智能搜索**：实时过滤查找目标账户。
* **剪贴板保护**：复制密码后 60 秒自动清空剪贴板，防止隐私泄露。
* **隐私模式**：支持一键切换密码显示/隐藏（••••••）。



## 🛠️ 技术栈

* **语言**：Python 3.x
* **GUI 框架**：Tkinter & ttk
* **加密库**：`hashlib`, `base64`, `hmac` (Python 标准库)
* **数据存储**：JSON (加密后存储于 `%APPDATA%`)
* **打包工具**：PyInstaller

## 🚀 快速开始

### 方式一：直接运行源码

由于本项目仅使用 Python 标准库，只要你安装了 Python 3，即可直接运行：

```bash
git clone https://github.com/你的用户名/SafeVault-Python.git
cd SafeVault-Python
python main.py

```

### 方式二：打包为 EXE (Windows)

如果你想生成一个独立的 `.exe` 文件分享给朋友，请按照以下步骤操作：

1. 安装 PyInstaller：
```bash
pip install pyinstaller

```


2. 执行打包命令（确保目录下有 `newlogo.ico` 图标文件）：
```bash
pyinstaller -F -w -i newlogo.ico --add-data "newlogo.ico;." main.py

```


3. 在 `dist/` 文件夹中找到 `main.exe` 即可运行。

## 🔐 安全架构说明

为了保证数据安全，本项目采用了以下加密流程：

1. **初始化**：用户设置主密码 -> 生成随机盐 (Salt) -> PBKDF2 派生密钥 -> 加密验证令牌 -> 存入 `data.json`。
2. **登录**：输入主密码 -> 读取 Salt -> 重新派生密钥 -> 尝试解密验证令牌 -> 成功则进入内存。
3. **存储**：所有账号密码在写入磁盘前，均使用 **Session Key + 随机 IV** 进行流加密。

## 📂 文件结构

```text
SafeVault-Python/
├── main.py          # 核心源码 (包含 UI、逻辑、加密层)
├── newlogo.ico      # 应用程序图标
├── .gitignore       # Git 忽略配置
└── README.md        # 项目说明书

```

## ⚠️ 注意事项

* **数据备份**：虽然数据是加密的，但建议定期备份 `%APPDATA%\MySecurePasswordApp\data.json` 文件。
* **主密码丢失**：由于采用了强加密技术，**一旦丢失主密码，所有数据将无法找回**，请务必牢记。

## 🤝 贡献

欢迎提交 Issue 或 Pull Request 来改进这个项目！

## 📄 许可证

MIT License

---


