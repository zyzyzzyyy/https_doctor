# HTTPS Doctor

一款轻量级的 HTTPS 证书诊断工具，支持批量检测网站的证书状态、加密套件安全性和证书链完整性。


## 下载

前往 [Releases](https://github.com/zyzyzzyyy/https_doctor/releases) 下载最新版本 `HTTPS_Doctor.exe`，直接运行即可。

## 功能特性

| 功能 | 说明 |
|------|------|
| **证书链检测** | 自动获取并展示完整证书链（服务器证书 → 中间证书 → 根证书），判断证书链是否完整 |
| **过期时间检测** | 显示证书到期时间，剩余天数一目了然 |
| **弱加密套件检测** | 自动识别弱加密套件（CBC 模式、RC4、3DES、MD5 等），显示警告 |
| **密钥交换算法** | 提取密钥交换方法（ECDHE/DHE/RSA/PSK） |
| **域名匹配验证** | 验证证书 CN 和 SAN 与访问域名是否匹配 |
| **证书吊销检测** | 支持 OCSP 和 CRL 两种方式查询证书吊销状态 |
| **批量检测** | 支持同时检测多个 URL，可并发检测提升效率 |
| **HTML 报告** | 导出详细的 HTML 检测报告 |
| **CSV 导出** | 导出检测结果为 CSV 文件，便于数据分析 |

## 异常原因优先级

检测结果中的异常原因按以下优先级显示（一票否决）：

| 优先级 | 异常类型 | 状态 |
|--------|----------|------|
| 1 | URL 无法访问 | 错误 |
| 2 | 检测失败 | 错误 |
| 3 | 证书已过期 | 错误 |
| 4 | 证书已被吊销 | 错误 |
| 5 | 证书与域名不匹配 | 错误 |
| 6 | 自签名证书 | 错误 |
| 7 | TLS 版本过低 | 警告 |

## 弱加密套件判断规则

以下加密套件会被标记为不安全：

- **无前向保密**：纯 RSA 密钥交换的 CBC 模式套件（如 `AES128-SHA`）
- **不安全算法**：包含 RC4、3DES、SEED、IDEA、MD5 的套件

## 使用方法

### 运行程序

1. 下载 `HTTPS_Doctor.exe`
2. 双击运行
3. 在输入框中输入 URL（支持多个，换行分隔）
4. 点击"开始检测"
5. 查看结果，可点击"导出 HTML 报告"或"导出 CSV"

### 从源码运行

```bash
pip install -r requirements.txt
python main.py
```

### 打包 exe

```bash
pip install pyinstaller
pyinstaller HTTPSDoctor_PySide6.spec --clean
```

生成的 exe 文件位于 `dist/HTTPS_Doctor.exe`。

## 项目结构

```
https_doctor/
├── main.py                # 程序入口
├── gui_pyside.py          # PySide6 GUI 主界面
├── gui.py                 # wxPython GUI（保留兼容）
├── cert_checker.py         # 证书检测核心逻辑
├── report_generator.py     # HTML/CSV 报告生成器
├── requirements.txt       # 依赖列表
└── HTTPSDoctor_PySide6.spec  # PyInstaller 打包配置
```

## 技术栈

- **Python 3.9+**
- **PySide6** - GUI 框架
- **cryptography** - 证书解析
- **certifi** - CA 证书

## 界面预览

- 现代化卡片式设计
- 状态图标：✓ 有效、⚠ 警告、✗ 错误
- 证书链可视化展示
- 详情面板显示 TLS 信息、域名验证、吊销状态
