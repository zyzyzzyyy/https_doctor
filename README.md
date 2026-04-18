# HTTPS Doctor

一款轻量级的 HTTPS 证书诊断工具，支持批量检测网站的证书状态、加密套件安全性和证书链完整性。

## 下载

前往 [Releases](https://github.com/zyzyzzyyy/https_doctor/releases) 下载最新版本 `HTTPS_Doctoer.exe`，直接运行即可。

## 功能特性

| 功能 | 说明 |
|------|------|
| **证书链检测** | 自动获取并展示完整证书链（服务器证书 → 中间证书 → 根证书），判断证书链是否完整 |
| **过期时间检测** | 显示证书到期时间，剩余 ≤30 天自动告警 |
| **弱加密套件检测** | 自动识别弱加密套件（CBC 模式、RC4、3DES、MD5 等），显示 ⚠️ 警告 |
| **密钥交换算法** | 提取密钥交换方法（ECDHE/DHE/RSA/PSK） |
| **域名匹配验证** | 验证证书 CN 和 SAN 与访问域名是否匹配 |
| **批量检测** | 支持同时检测多个 URL |
| **HTML 报告** | 导出详细的检测报告 |

## 弱加密套件判断规则

以下加密套件会被标记为不安全：

- **无前向保密**：纯 RSA 密钥交换的 CBC 模式套件（如 `AES128-SHA`）
- **不安全算法**：包含 RC4、3DES、SEED、IDEA、MD5 的套件

## 使用方法

### 运行程序

1. 下载 `HTTPS_Doctoer.exe`
2. 双击运行
3. 在输入框中输入 URL（支持多个，换行分隔）
4. 点击"开始检测"
5. 查看结果，可点击"导出报告"生成 HTML 报告

### 从源码运行

```bash
pip install -r requirements.txt
python main.py
```

### 打包 exe

```bash
pip install pyinstaller
pyinstaller HTTPSDoctor.spec --clean
```

生成的 exe 文件位于 `dist/HTTPS_Doctoer.exe`。

## 项目结构

```
https_doctor/
├── main.py              # 程序入口
├── gui.py               # wxPython GUI 界面
├── cert_checker.py      # 证书检测核心逻辑
├── report_generator.py  # HTML 报告生成器
└── requirements.txt     # 依赖列表
```

## 技术栈

- **Python 3.9+**
- **wxPython** - GUI 框架
- **cryptography** - 证书解析
- **certifi** - CA 证书
