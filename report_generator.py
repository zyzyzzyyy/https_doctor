"""
CSV 报告生成器 - HTTPS 证书检测工具
根据证书检测结果生成 CSV 文件。
"""

import csv
from typing import List, Dict, Any


def generate_csv_report(results: List[Dict[str, Any]], output_path: str) -> None:
    """
    根据证书检测结果生成 CSV 报告。

    参数:
        results: cert_checker 返回的结果字典列表
        output_path: 保存 CSV 文件的路径
    """
    headers = [
        "URL",
        "状态",
        "过期时间",
        "剩余天数",
        "证书链完整",
        "证书链",
        "TLS版本",
        "加密套件",
        "密钥交换",
        "弱加密",
        "域名匹配",
        "证书CN",
        "证书SAN",
        "吊销状态",
        "吊销详情",
        "错误信息"
    ]

    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)

        for result in results:
            row = _build_row(result)
            writer.writerow(row)


def _build_row(result: Dict[str, Any]) -> List[str]:
    """将单个检测结果转换为 CSV 行"""
    status_map = {"valid": "有效", "warning": "警告", "error": "错误"}

    url = result.get("url", "")
    status = status_map.get(result.get("status", ""), result.get("status", ""))

    expiry = result.get("expiry", {})
    expire_date = expiry.get("expire_date", "") if expiry else ""
    days_left = str(expiry.get("days_left", "")) if expiry else ""

    cert_chain_complete = "是" if result.get("cert_chain_complete", False) else "否"

    cert_chain = result.get("cert_chain", [])
    cert_chain_str = "; ".join([
        f"{c.get('type', '')}:{c.get('name', '')}" for c in cert_chain
    ]) if cert_chain else ""

    tls = result.get("tls", {})
    tls_version = tls.get("version", "") if tls else ""
    cipher_suite = tls.get("cipher_suite", "") if tls else ""
    key_exchange = tls.get("key_exchange", "") if tls else ""
    cipher_weak = "是" if (tls.get("cipher_weak", False) if tls else False) else "否"

    domain_match = result.get("domain_match", {})
    match = "是" if (domain_match.get("match", False) if domain_match else False) else "否"
    cert_cn = domain_match.get("cert_cn", "") if domain_match else ""
    cert_san = "; ".join(domain_match.get("cert_san", [])) if domain_match else ""

    revocation = result.get("revocation", {})
    revocation_status_raw = revocation.get("status", "") if revocation else ""

    # 判断状态描述
    if revocation_status_raw == "ok":
        revocation_status = "正常"
        revocation_detail = ""
    elif revocation_status_raw == "revoked":
        revocation_status = "已吊销"
        revocation_detail = revocation.get("crl_response", revocation.get("ocsp_response", ""))
    elif revocation_status_raw == "error":
        revocation_status = "查询失败"
        revocation_detail = revocation.get("ocsp_response", "")
    elif revocation_status_raw == "unknown":
        revocation_status = "未知"
        revocation_detail = revocation.get("ocsp_response", revocation.get("crl_response", ""))
    else:
        revocation_status = revocation_status_raw
        revocation_detail = revocation.get("ocsp_response", "")

    error_message = result.get("error_message", "")

    return [
        url,
        status,
        expire_date,
        days_left,
        cert_chain_complete,
        cert_chain_str,
        tls_version,
        cipher_suite,
        key_exchange,
        cipher_weak,
        match,
        cert_cn,
        cert_san,
        revocation_status,
        revocation_detail,
        error_message
    ]


"""
HTML 报告生成器 - HTTPS 证书检测工具
根据证书检测结果生成 HTML 报告。
"""

from datetime import datetime
from typing import List, Dict, Any


def generate_html_report(results: List[Dict[str, Any]], output_path: str) -> None:
    """
    根据证书检测结果生成 HTML 报告。

    参数:
        results: cert_checker 返回的结果字典列表
        output_path: 保存 HTML 报告的路径
    """
    total = len(results)
    valid_count = sum(1 for r in results if r.get("status") == "valid")
    warning_count = sum(1 for r in results if r.get("status") == "warning")
    error_count = sum(1 for r in results if r.get("status") == "error")

    html_content = _build_html(results, total, valid_count, warning_count, error_count)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def _build_html(
    results: List[Dict[str, Any]],
    total: int,
    valid_count: int,
    warning_count: int,
    error_count: int,
) -> str:
    """构建完整的 HTML 文档。"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTPS 证书检测报告</title>
    <style>
        {STYLES}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>HTTPS 证书检测报告</h1>
            <p class="timestamp">检测时间: {timestamp}</p>
        </header>

        <section class="summary">
            <h2>检测概览</h2>
            <div class="stats">
                <div class="stat total">
                    <span class="stat-value">{total}</span>
                    <span class="stat-label">检测总数</span>
                </div>
                <div class="stat valid">
                    <span class="stat-value">{valid_count}</span>
                    <span class="stat-label">有效</span>
                </div>
                <div class="stat warning">
                    <span class="stat-value">{warning_count}</span>
                    <span class="stat-label">警告</span>
                </div>
                <div class="stat error">
                    <span class="stat-value">{error_count}</span>
                    <span class="stat-label">失败</span>
                </div>
            </div>
        </section>

        <section class="results">
            <h2>检测结果详情</h2>
            <table>
                <thead>
                    <tr>
                        <th>状态</th>
                        <th>URL</th>
                        <th>过期时间</th>
                        <th>证书链</th>
                        <th>TLS版本</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(_generate_result_rows(results))}
                </tbody>
            </table>
        </section>

        <section class="details">
            <h2>详细信息</h2>
            {"".join(_generate_detail_sections(results))}
        </section>
    </div>
</body>
</html>"""
    return html


def _generate_result_rows(results: List[Dict[str, Any]]) -> List[str]:
    """为每个结果生成表格行。"""
    rows = []
    for r in results:
        status = r.get("status", "error")
        url = r.get("url", "Unknown")
        expiry_info = r.get("expiry", {})
        cert_chain_complete = r.get("cert_chain_complete", False)
        tls_info = r.get("tls", {})

        status_icon = STATUS_ICONS.get(status, STATUS_ICONS["error"])
        status_class = f"status-{status}"

        # Calculate expiry display
        if expiry_info.get("expired"):
            expiry_display = "已过期"
        elif expiry_info.get("days_left") is not None:
            days = expiry_info["days_left"]
            expiry_display = f"{days}天后"
        else:
            expiry_display = "未知"

        # Certificate chain display
        chain_display = "完整" if cert_chain_complete else "不完整"

        # TLS version display
        tls_display = tls_info.get("version", "未知")

        row = f"""
                    <tr class="{status_class}">
                        <td class="status-cell">{status_icon}</td>
                        <td>{url}</td>
                        <td>{expiry_display}</td>
                        <td>{chain_display}</td>
                        <td>{tls_display}</td>
                    </tr>"""
        rows.append(row)
    return rows


def _generate_detail_sections(results: List[Dict[str, Any]]) -> List[str]:
    """为每个结果生成详情区块。"""
    sections = []
    for r in results:
        url = r.get("url", "Unknown")
        status = r.get("status", "error")

        section = f"""
            <div class="detail-block {status}">
                <h3>{url}</h3>
                {_generate_cert_chain_detail(r)}
                {_generate_tls_detail(r)}
                {_generate_domain_detail(r)}
                {_generate_revocation_detail(r)}
                {f'<p class="error-message">{r.get("error_message", "")}</p>' if r.get("error_message") else ""}
            </div>"""
        sections.append(section)
    return sections


def _generate_cert_chain_detail(r: Dict[str, Any]) -> str:
    """生成证书链详情区块。"""
    cert_chain = r.get("cert_chain", [])

    if not cert_chain:
        return "<p>证书链信息不可用</p>"

    chain_items = []
    for cert in cert_chain:
        cert_type = cert.get("type", "unknown")
        cert_name = cert.get("name", "Unknown")
        cert_status = cert.get("status", "unknown")

        type_label = {"root": "Root CA", "intermediate": "Intermediate", "server": "Server"}
        label = type_label.get(cert_type, cert_type)

        icon = "&#10003;" if cert_status == "ok" else "&#10007;"
        chain_items.append(f"<li><strong>{label}:</strong> {cert_name} {icon}</li>")

    chain_complete = r.get("cert_chain_complete", False)
    complete_status = "&#10003; 完整" if chain_complete else "&#10007; 不完整"

    return f"""
        <div class="detail-section">
            <h4>证书链</h4>
            <ul class="cert-chain">
                {"".join(chain_items)}
            </ul>
            <p class="chain-status">状态: {complete_status}</p>
        </div>"""


def _generate_tls_detail(r: Dict[str, Any]) -> str:
    """生成 TLS 详情区块。"""
    tls = r.get("tls", {})
    if not tls:
        return ""

    version = tls.get("version", "未知")
    cipher = tls.get("cipher_suite", "未知")
    if tls.get("cipher_weak"):
        cipher = f"<span style='color:#e67e22'>⚠️ {cipher}</span>"
    key_exchange = tls.get("key_exchange", "未知")

    return f"""
        <div class="detail-section">
            <h4>TLS 信息</h4>
            <ul>
                <li><strong>版本:</strong> {version}</li>
                <li><strong>加密套件:</strong> {cipher}</li>
                <li><strong>密钥交换:</strong> {key_exchange}</li>
            </ul>
        </div>"""


def _generate_domain_detail(r: Dict[str, Any]) -> str:
    """生成域名验证详情区块。"""
    domain = r.get("domain_match", {})
    if not domain:
        return ""

    match = domain.get("match", False)
    cn = domain.get("cert_cn", "未知")
    san = domain.get("cert_san", [])

    match_status = "&#10003; 匹配" if match else "&#10007; 不匹配"
    san_display = ", ".join(san) if san else "无"

    return f"""
        <div class="detail-section">
            <h4>域名验证</h4>
            <ul>
                <li><strong>匹配状态:</strong> {match_status}</li>
                <li><strong>证书CN:</strong> {cn}</li>
                <li><strong>证书SAN:</strong> {san_display}</li>
            </ul>
        </div>"""


def _generate_revocation_detail(r: Dict[str, Any]) -> str:
    """生成吊销状态详情区块。"""
    revocation = r.get("revocation", {})
    if not revocation:
        return ""

    status = revocation.get("status", "unknown")
    ocsp = revocation.get("ocsp_response", "")

    status_text = {"ok": "正常", "revoked": "已吊销", "unknown": "未知", "error": "查询失败"}
    status_display = status_text.get(status, status)

    return f"""
        <div class="detail-section">
            <h4>吊销状态</h4>
            <ul>
                <li><strong>状态:</strong> {status_display}</li>
                {f'<li><strong>OCSP响应:</strong> {ocsp}</li>' if ocsp else ""}
            </ul>
        </div>"""


STATUS_ICONS = {
    "valid": "&#10003;",
    "warning": "&#9888;",
    "error": "&#10007;",
}

STYLES = """
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        line-height: 1.6;
        color: #333;
        background: #f5f5f5;
    }

    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
    }

    header {
        background: linear-gradient(135deg, #1a73e8 0%, #0d47a1 100%);
        color: white;
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 20px;
    }

    header h1 {
        font-size: 28px;
        margin-bottom: 8px;
    }

    .timestamp {
        opacity: 0.9;
        font-size: 14px;
    }

    .summary {
        background: white;
        padding: 24px;
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .summary h2 {
        font-size: 18px;
        margin-bottom: 16px;
        color: #333;
    }

    .stats {
        display: flex;
        gap: 16px;
    }

    .stat {
        flex: 1;
        padding: 16px;
        border-radius: 6px;
        text-align: center;
    }

    .stat.total {
        background: #e3f2fd;
    }

    .stat.valid {
        background: #e8f5e9;
    }

    .stat.warning {
        background: #fff8e1;
    }

    .stat.error {
        background: #ffebee;
    }

    .stat-value {
        display: block;
        font-size: 32px;
        font-weight: bold;
    }

    .stat-label {
        font-size: 13px;
        color: #666;
    }

    .results {
        background: white;
        padding: 24px;
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .results h2 {
        font-size: 18px;
        margin-bottom: 16px;
    }

    table {
        width: 100%;
        border-collapse: collapse;
    }

    th, td {
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #eee;
    }

    th {
        background: #f8f9fa;
        font-weight: 600;
        color: #555;
    }

    .status-cell {
        font-size: 18px;
    }

    tr.status-valid {
        background: #fafafa;
    }

    tr.status-warning {
        background: #fff8e1;
    }

    tr.status-error {
        background: #ffebee;
    }

    .details {
        background: white;
        padding: 24px;
        border-radius: 8px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .details h2 {
        font-size: 18px;
        margin-bottom: 16px;
    }

    .detail-block {
        border: 1px solid #eee;
        border-radius: 6px;
        padding: 16px;
        margin-bottom: 16px;
    }

    .detail-block.valid {
        border-left: 4px solid #4caf50;
    }

    .detail-block.warning {
        border-left: 4px solid #ff9800;
    }

    .detail-block.error {
        border-left: 4px solid #f44336;
    }

    .detail-block h3 {
        font-size: 16px;
        margin-bottom: 12px;
        word-break: break-all;
    }

    .detail-section {
        margin-bottom: 16px;
    }

    .detail-section:last-child {
        margin-bottom: 0;
    }

    .detail-section h4 {
        font-size: 14px;
        color: #666;
        margin-bottom: 8px;
    }

    .detail-section ul {
        list-style: none;
        padding-left: 0;
    }

    .detail-section li {
        padding: 4px 0;
        font-size: 14px;
    }

    .cert-chain {
        border-left: 2px solid #ddd;
        padding-left: 16px !important;
        margin-left: 8px;
    }

    .cert-chain li {
        margin: 8px 0;
    }

    .chain-status {
        margin-top: 8px;
        font-weight: 600;
    }

    .error-message {
        color: #d32f2f;
        font-weight: 500;
        margin-top: 12px;
    }
"""