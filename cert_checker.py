"""
HTTPS 证书检测工具 - 核心检测逻辑（纯函数，无 GUI 依赖）
"""

import ssl
import socket
import datetime
import re
import time
from urllib.parse import urlparse
import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives.serialization import pkcs7


def _retry_on_failure(max_retries: int = 3, delay: float = 0.5):
    """连接重试装饰器"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (socket.timeout, socket.gaierror, ConnectionRefusedError, ssl.SSLError, OSError) as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        time.sleep(delay)
            raise last_exception
        return wrapper
    return decorator


@_retry_on_failure(max_retries=3, delay=0.5)
def _ssl_connect_with_retry(context, host, port):
    """带重试的SSL连接"""
    sock = socket.create_connection((host, port), timeout=30)
    try:
        ssock = context.wrap_socket(sock, server_hostname=host)
        cert_der = ssock.getpeercert(binary_form=True)
        if cert_der is None:
            return None
        tls_version = ssock.version()
        cipher_suite = ssock.cipher()
        return cert_der, tls_version, cipher_suite
    finally:
        sock.close()


def _is_self_signed(cert) -> bool:
    """判断是否为自签名证书（签发者与主体相同）"""
    try:
        return cert.subject == cert.issuer
    except Exception:
        return False


def check_certificate(url: str) -> dict:
    """
    检测指定 URL 的证书状态。

    参数:
        url: 要检测的 HTTPS URL

    返回:
        dict: 包含证书分析结果的字典
    """
    # 初始化结果字典
    result = {
        "url": url,
        "status": "error",  # 默认状态为错误
        "error_message": None,
        "cert_chain": [],  # 证书链列表
        "cert_chain_complete": False,  # 证书链是否完整
        "expiry": {  # 过期信息
            "expired": False,
            "days_left": None,
            "expire_date": None
        },
        "revocation": {  # 吊销状态
            "status": "unknown",
            "ocsp_response": ""
        },
        "domain_match": {  # 域名匹配
            "match": False,
            "cert_cn": "",
            "cert_san": []
        },
        "tls": {  # TLS 信息
            "version": "",
            "cipher_suite": "",
            "key_exchange": "",
            "cipher_weak": False
        },
        "issues": []  # 异常原因列表
    }

    # 解析 URL 获取主机名和端口
    parsed = urlparse(url)
    host = str(parsed.hostname) if parsed.hostname else ""  # 确保是字符串
    port = parsed.port or 443  # 默认 HTTPS 端口 443

    try:
        # 创建 SSL 上下文
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # IP地址不需要hostname检查，允许获取证书信息（即使域名不匹配或自签名）
        if _is_ip_address(host):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # IP地址跳过证书验证
        else:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=certifi.where())

        # 使用重试机制连接服务器并获取证书信息
        cert_data = _ssl_connect_with_retry(context, host, port)
        if cert_data is None:
            raise ValueError("无法获取证书信息")

        cert_der, tls_version, cipher_suite = cert_data

        # 使用 cryptography 库解析证书
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # 从服务器的证书链构建证书链信息
        cert_chain = []
        try:
            # 首先添加服务器证书
            server_name = _get_cert_name(cert)
            cert_chain.append({
                "type": "server",
                "name": server_name,
                "status": "ok"
            })

            # 尝试通过 AIA 获取中间证书
            issuer_cert = _get_issuer_from_aia(cert, host)
            if issuer_cert is not None:
                issuer_type = _get_cert_type(issuer_cert)
                issuer_name = _get_cert_name(issuer_cert)
                if issuer_name != server_name:
                    cert_chain.append({
                        "type": issuer_type,
                        "name": issuer_name,
                        "status": "ok"
                    })
                # 尝试获取根证书
                root_issuer = _get_issuer_from_aia(issuer_cert, host)
                if root_issuer is not None:
                    root_type = _get_cert_type(root_issuer)
                    root_name = _get_cert_name(root_issuer)
                    if root_name != issuer_name and root_name != server_name:
                        cert_chain.append({
                            "type": root_type,
                            "name": root_name,
                            "status": "ok"
                        })
        except (AttributeError, Exception):
            pass

        # 确保至少包含服务器证书
        if not cert_chain:
            cert_chain.append({
                "type": "server",
                "name": _get_cert_name(cert),
                "status": "ok"
            })

        # 检查证书链完整性
        # 完整链应包含服务器证书以及根 CA 或中间 CA
        has_root = any(c["type"] == "root" for c in cert_chain)
        has_intermediate = any(c["type"] == "intermediate" for c in cert_chain)
        has_server = any(c["type"] == "server" for c in cert_chain)

        result["cert_chain"] = cert_chain
        # 完整链应包含服务器证书 + 根CA或中间CA
        result["cert_chain_complete"] = (has_root or has_intermediate) and has_server

        # 检查证书过期时间
        expiry_date = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (expiry_date - now).days
        expired = expiry_date < now

        result["expiry"] = {
            "expired": expired,
            "days_left": days_left,
            "expire_date": expiry_date.strftime("%Y-%m-%d %H:%M:%S UTC")
        }

        # 根据过期时间添加到异常列表
        if expired:
            result["issues"].append("证书已过期")
        elif days_left is not None and days_left <= 20:
            result["issues"].append(f"证书即将在{days_left}天内到期")

        # 检查域名匹配
        cn = _get_cn(cert)
        san_list = _get_san(cert)
        match = _verify_domain_match(host, cn, san_list)

        result["domain_match"] = {
            "match": match,
            "cert_cn": cn,
            "cert_san": san_list
        }

        # IP地址或域名不匹配时，添加到异常列表
        if not match:
            if _is_ip_address(host):
                result["issues"].append("未使用域名")
            else:
                result["issues"].append("证书与域名不匹配")

        # 检查证书吊销状态（优先 OCSP，失败则尝试 CRL）
        revocation_result = _check_ocsp(cert, host, port)

        # 如果 OCSP 因网络问题失败，尝试 CRL 作为备用
        if revocation_result["status"] == "error" and "查询失败" in revocation_result.get("ocsp_response", ""):
            crl_result = _check_crl(cert, host)
            if crl_result["status"] != "unknown":
                revocation_result = {
                    "status": crl_result["status"],
                    "ocsp_response": revocation_result["ocsp_response"],
                    "crl_response": crl_result.get("crl_response", "")
                }
            else:
                revocation_result = {
                    "status": "unknown",
                    "ocsp_response": revocation_result["ocsp_response"] + "；CRL 也无法查询"
                }

        result["revocation"] = revocation_result

        # 检查证书是否被吊销
        if revocation_result["status"] == "revoked":
            result["issues"].append("证书已被吊销")

        # 获取 TLS 信息
        result["tls"] = {
            "version": tls_version,
            "cipher_suite": cipher_suite[0] if cipher_suite else "",
            "key_exchange": _get_key_exchange_method(cipher_suite[0] if cipher_suite else ""),
            "cipher_weak": _is_weak_cipher(cipher_suite[0] if cipher_suite else "")
        }

        # 收集所有异常（暂存）
        all_issues = []

        # 检查证书已过期
        if expired:
            all_issues.append(("证书已过期", "error"))

        # 检查证书即将过期
        if days_left is not None and days_left <= 20 and not expired:
            all_issues.append((f"证书即将在{days_left}天内到期", "warning"))

        # 检查证书被吊销
        if revocation_result["status"] == "revoked":
            all_issues.append(("证书已被吊销", "error"))

        # 检查未使用域名（IP访问）
        if _is_ip_address(host):
            all_issues.append(("未使用域名", "error"))

        # 检查自签名证书
        if _is_self_signed(cert):
            all_issues.append(("证书为自签名", "error"))

        # 检查域名不匹配（仅非IP访问时）
        if not match and not _is_ip_address(host):
            all_issues.append(("证书与域名不匹配", "error"))

        # 检查弱密码套件
        if result["tls"]["cipher_weak"]:
            all_issues.append(("使用了弱密码套件", "warning"))

        # 检查TLS版本过低
        if tls_version in ("TLSv1", "TLSv1.1"):
            all_issues.append(("TLS版本过低", "warning"))

        # 检查证书链不完整
        if not result["cert_chain_complete"]:
            all_issues.append(("证书链不完整", "warning"))

        # 一票否决：根据优先级确定最终状态
        # 优先级: URL无法访问 > 检测失败 > 证书已过期 > 证书已被吊销 > 未使用域名 > 自签名证书 > 其他
        critical_errors = {
            "证书已过期", "证书已被吊销", "未使用域名", "证书为自签名", "证书与域名不匹配"
        }

        final_issues = []
        final_status = "valid"

        # 检查是否有critical error
        for issue_text, issue_type in all_issues:
            if issue_text in critical_errors:
                final_issues = [issue_text]
                final_status = "error"
                break

        # 如果没有critical error，显示所有其他问题
        if not final_issues:
            for issue_text, issue_type in all_issues:
                final_issues.append(issue_text)
                if issue_type == "error":
                    final_status = "error"
                elif issue_type == "warning" and final_status == "valid":
                    final_status = "warning"

        result["issues"] = final_issues
        result["status"] = final_status

    except socket.gaierror as e:
        result["issues"].append("URL无法访问")
        result["status"] = "error"
        result["cert_chain"] = []
        result["cert_chain_complete"] = False
        result["expiry"] = {"expired": False, "days_left": None, "expire_date": None}
        result["tls"] = {"version": "", "cipher_suite": "", "key_exchange": "", "cipher_weak": False}
    except socket.timeout:
        result["issues"].append("URL无法访问")
        result["status"] = "error"
        result["cert_chain"] = []
        result["cert_chain_complete"] = False
        result["expiry"] = {"expired": False, "days_left": None, "expire_date": None}
        result["tls"] = {"version": "", "cipher_suite": "", "key_exchange": "", "cipher_weak": False}
    except ConnectionRefusedError:
        result["issues"].append("URL无法访问")
        result["status"] = "error"
        result["cert_chain"] = []
        result["cert_chain_complete"] = False
        result["expiry"] = {"expired": False, "days_left": None, "expire_date": None}
        result["tls"] = {"version": "", "cipher_suite": "", "key_exchange": "", "cipher_weak": False}
    except ssl.SSLCertVerificationError as e:
        # 证书验证失败时，尝试禁用验证获取证书信息
        try:
            ctx_no_verify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_no_verify.check_hostname = False
            ctx_no_verify.verify_mode = ssl.CERT_NONE
            cert_data = _ssl_connect_with_retry(ctx_no_verify, host, port)
            if cert_data:
                cert_der, tls_version, cipher_suite = cert_data
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                # 检查是否为自签名证书
                if _is_self_signed(cert):
                    result["issues"].append("证书为自签名")
                    result["status"] = "error"

                # 检查证书过期时间
                expiry_date = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                days_left = (expiry_date - now).days
                expired = expiry_date < now

                result["expiry"] = {
                    "expired": expired,
                    "days_left": days_left,
                    "expire_date": expiry_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                }

                if expired and "证书为自签名" not in result["issues"]:
                    result["issues"].append("证书已过期")
                    result["status"] = "error"
                elif "证书为自签名" not in result["issues"]:
                    # 判断是否为根证书缺失的环境问题
                    error_msg = str(e).lower()
                    if "unable to get local issuer" in error_msg or "unable to find" in error_msg:
                        # 根证书缺失，服务器未发送完整证书链
                        result["issues"].append("证书链不完整")
                        result["status"] = "warning"
                    else:
                        result["issues"].append("证书验证失败")
                        result["status"] = "error"
            else:
                result["issues"].append("证书验证失败")
                result["status"] = "error"
        except Exception:
            result["issues"].append("证书验证失败")
            result["status"] = "error"
    except Exception as e:
        result["issues"].append("检测失败")
        result["status"] = "error"
        result["cert_chain"] = []
        result["cert_chain_complete"] = False
        result["expiry"] = {"expired": False, "days_left": None, "expire_date": None}
        result["tls"] = {"version": "", "cipher_suite": "", "key_exchange": "", "cipher_weak": False}

    return result


def _get_cert_type(cert):
    """
    判断证书类型（根证书、中间证书或服务器证书）。

    判断逻辑:
    - 自签名证书（subject == issuer）为根证书
    - 具有 CA 基本约束扩展的为中间证书
    - 其他为服务器证书
    """
    try:
        # 自签名证书很可能是根证书
        if cert.subject == cert.issuer:
            return "root"
        # 检查基本约束扩展以确定是否为 CA
        try:
            basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            if basic_constraints.value.ca:
                return "intermediate"
        except x509.ExtensionNotFound:
            pass
    except Exception:
        pass
    return "server"


def _get_cert_name(cert):
    """
    获取证书名称，优先使用 CN（通用名称），其次使用组织名称。
    """
    try:
        # 尝试获取通用名称
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                return attr.value
    except Exception:
        pass

    try:
        # 尝试获取组织名称
        org = cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        if org:
            return org[0].value
    except Exception:
        pass

    # 如果都无法获取，返回完整的 subject 字符串
    return str(cert.subject)


def _get_cn(cert):
    """
    从证书中获取通用名称（Common Name）。
    """
    try:
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                return attr.value
    except Exception:
        pass
    return ""


def _get_san(cert):
    """
    从证书中获取主题备用名称（Subject Alternative Name）列表。
    """
    san_list = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = [name.value for name in san_ext.value]
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    return san_list


def _verify_domain_match(host, cn, san_list):
    """
    验证访问的主机名是否与证书的 CN 或 SAN 匹配。

    支持:
    - 直接匹配
    - 通配符匹配（如 *.example.com 匹配 sub.example.com）
    - IP地址匹配
    """
    # 转换为字符串进行比较
    host = str(host) if host else ""
    cn = str(cn) if cn else ""

    # 直接匹配
    if cn == host:
        return True

    # 通配符匹配
    if cn.startswith("*."):
        base_domain = cn[2:]
        if host.endswith(base_domain) and host != base_domain:
            return True

    # SAN 匹配
    for san in san_list:
        san = str(san) if san else ""
        if san == host:
            return True
        if san.startswith("*."):
            base_domain = san[2:]
            if host.endswith(base_domain) and host != base_domain:
                return True

    return False


def _is_ip_address(host: str) -> bool:
    """判断是否为IP地址"""
    # IPv4地址
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, host):
        return True
    # IPv6地址（简化判断）
    if ':' in host:
        return True
    return False


def _check_ocsp(cert, host, port):
    """
    通过 OCSP（在线证书状态协议）检查证书是否被吊销。
    """
    try:
        # 从证书的 AIA 扩展获取 OCSP URI
        ocsp_uri = None
        try:
            aia_ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for ad in aia_ext.value:
                if ad.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    ocsp_uri = ad.access_location.value
                    break
        except x509.ExtensionNotFound:
            return {"status": "unknown", "ocsp_response": "未找到 OCSP 地址"}
        except Exception:
            pass

        if not ocsp_uri:
            return {"status": "unknown", "ocsp_response": "未找到 OCSP 地址"}

        # 构建 OCSP 请求需要颁发者证书
        # 从 AIA 扩展获取颁发者证书
        issuer_cert = _get_issuer_from_aia(cert, host)
        if issuer_cert is None:
            return {"status": "unknown", "ocsp_response": "无法获取颁发者证书"}

        # 构建 OCSP 请求
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
        request = builder.build()
        request_data = request.public_bytes(serialization.Encoding.DER)

        # 发送 OCSP 请求
        ocsp_parsed = urlparse(ocsp_uri)
        ocsp_host = ocsp_parsed.netloc or ocsp_parsed.path.split(":")[0] if ":" in ocsp_parsed.path else ocsp_parsed.path

        # 解析端口号
        if ":" in ocsp_parsed.netloc:
            ocsp_host, ocsp_port_str = ocsp_parsed.netloc.split(":")
            ocsp_port = int(ocsp_port_str)
        else:
            ocsp_port = 80

        path = ocsp_parsed.path or "/"
        if ocsp_parsed.query:
            path += "?" + ocsp_parsed.query

        with socket.create_connection((ocsp_host, ocsp_port), timeout=5) as sock:
            sock.sendall(
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {ocsp_host}:{ocsp_port}\r\n"
                f"Content-Type: application/ocsp-request\r\n"
                f"Content-Length: {len(request_data)}\r\n"
                f"Connection: close\r\n"
                f"\r\n".encode() + request_data
            )

            # 读取响应
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break

            # 解析 HTTP 响应
            if not response:
                return {"status": "error", "ocsp_response": "OCSP 服务器无响应"}

            # 简单 HTTP 响应解析
            header_end = response.find(b"\r\n\r\n")
            if header_end == -1:
                return {"status": "error", "ocsp_response": "OCSP 响应格式错误"}

            headers = response[:header_end].decode("utf-8", errors="ignore")
            body = response[header_end + 4:]

            # 检查 HTTP 状态码
            status_line = headers.split("\r\n")[0]
            if "200" not in status_line and "201" not in status_line:
                return {"status": "unknown", "ocsp_response": f"OCSP 查询失败: HTTP {status_line}"}

            # 解析 OCSP 响应
            if b"Successful" in body or b"good" in body.lower():
                return {"status": "ok", "ocsp_response": "证书未被吊销"}
            elif b"revoked" in body.lower():
                return {"status": "revoked", "ocsp_response": "证书已被吊销"}
            else:
                return {"status": "unknown", "ocsp_response": "无法解析 OCSP 响应"}

    except socket.timeout:
        return {"status": "error", "ocsp_response": "OCSP 查询超时"}
    except Exception as e:
        return {"status": "error", "ocsp_response": f"OCSP 查询失败: {str(e)}"}


def _check_crl(cert, host):
    """
    通过 CRL（证书吊销列表）检查证书是否被吊销。
    CRL 通常托管在境内 CDN 上，在中国网络环境下更可靠。
    """
    try:
        # 从证书的 CRL 分发点扩展获取 CRL 地址
        crl_dp = None
        try:
            crl_ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            if crl_ext.value:
                for dp in crl_ext.value:
                    if dp.full_name:
                        crl_dp = dp.full_name[0].value
                        break
        except x509.ExtensionNotFound:
            return {"status": "unknown", "crl_response": "未找到 CRL 分发点"}
        except Exception:
            pass

        if not crl_dp:
            return {"status": "unknown", "crl_response": "未找到 CRL 分发点"}

        # 下载 CRL 文件
        parsed = urlparse(crl_dp)
        crl_host = parsed.netloc or parsed.path.split("/")[0]
        crl_path = "/" + "/".join(parsed.path.split("/")[1:]) if parsed.path and "/" in parsed.path else "/"

        # 解析端口
        if ":" in crl_host:
            crl_host, crl_port_str = crl_host.split(":")
            crl_port = int(crl_port_str)
        else:
            crl_port = 443 if parsed.scheme == "https" else 80

        # 尝试 HTTPS 和 HTTP
        response = b""
        schemes = ["https", "http"] if parsed.scheme == "http" else ["https"]

        for scheme in schemes:
            if response:
                break
            try:
                with socket.create_connection((crl_host, crl_port), timeout=5) as sock:
                    if scheme == "https":
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        with context.wrap_socket(sock) as ssock:
                            request = f"GET {crl_path} HTTP/1.1\r\nHost: {crl_host}\r\nConnection: close\r\n\r\n"
                            ssock.sendall(request.encode())
                            response = _recv_all(ssock)
                    else:
                        request = f"GET {crl_path} HTTP/1.1\r\nHost: {crl_host}\r\nConnection: close\r\n\r\n"
                        sock.sendall(request.encode())
                        response = _recv_all(sock)
            except Exception:
                continue

        if not response:
            return {"status": "unknown", "crl_response": "无法下载 CRL"}

        # 跳过 HTTP header
        header_end = response.find(b"\r\n\r\n")
        body = response[header_end + 4:] if header_end >= 0 else response

        # 尝试解析 CRL
        try:
            crl = x509.load_der_x509_crl(body, default_backend())

            # 检查证书是否在 CRL 中
            try:
                revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
                if revoked_cert:
                    revocation_date = revoked_cert.revocation_date.strftime("%Y-%m-%d")
                    return {"status": "revoked", "crl_response": f"证书已被吊销 (撤销日期: {revocation_date})"}
            except AttributeError:
                pass

            # 证书不在 CRL 中
            return {"status": "ok", "crl_response": "证书未被吊销 (CRL检查)"}

        except Exception:
            return {"status": "unknown", "crl_response": "无法解析 CRL 格式"}

    except Exception as e:
        return {"status": "unknown", "crl_response": f"CRL 检查失败: {str(e)}"}


def _get_issuer_from_aia(cert, host):
    """
    从证书的 AIA（授权信息访问）扩展获取并下载颁发者证书。

    AIA 扩展包含 CA_ISSUERS 项，指向颁发者证书的下载位置。
    """
    try:
        # 获取 AIA 扩展中的颁发者 URL
        aia_ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        issuer_url = None
        for ad in aia_ext.value:
            if ad.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                issuer_url = ad.access_location.value
                break

        if not issuer_url:
            return None

        # 下载颁发者证书
        parsed = urlparse(issuer_url)
        issuer_host = parsed.netloc or parsed.path.split("/")[0]
        issuer_path = "/" + "/".join(parsed.path.split("/")[1:]) if parsed.path else "/"

        # 解析端口
        if ":" in issuer_host:
            ih, ip = issuer_host.split(":")
            ip = int(ip)
        else:
            ih = issuer_host
            ip = 443 if parsed.scheme == "https" else 80

        # 首先尝试 HTTPS
        response = b""
        if parsed.scheme == "https" or ip == 443:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ih, ip), timeout=5) as sock:
                    with context.wrap_socket(sock) as ssock:
                        request = f"GET {issuer_path} HTTP/1.1\r\nHost: {ih}\r\nConnection: close\r\n\r\n"
                        ssock.sendall(request.encode())
                        response = _recv_all(ssock)
            except Exception:
                pass

        # 如果 HTTPS 失败，尝试 HTTP
        if not response:
            try:
                http_port = 80 if ip == 443 else ip
                with socket.create_connection((ih, http_port), timeout=5) as sock:
                    request = f"GET {issuer_path} HTTP/1.1\r\nHost: {ih}\r\nConnection: close\r\n\r\n"
                    sock.sendall(request.encode())
                    response = _recv_all(sock)
            except Exception:
                pass

        # 解析证书
        return _parse_cert_from_response(response)

    except Exception:
        pass

    return None


def _recv_all(sock):
    """接收套接字所有数据"""
    response = b""
    while True:
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            response += chunk
            # 如果数据量较大且已找到证书结束标记，提前退出
            if len(response) > 10000 and b"-----END CERTIFICATE-----" in response:
                break
        except Exception:
            break
    return response


def _parse_cert_from_response(response):
    """从 HTTP 响应中解析证书"""
    if not response:
        return None

    # 跳过 HTTP header
    header_end = response.find(b"\r\n\r\n")
    if header_end >= 0:
        body = response[header_end + 4:]
    else:
        body = response

    # 检查是否为 PKCS#7 格式
    if b"pkcs7" in body.lower() or body.startswith(b"0"):
        certs = _parse_pkcs7(body)
        if certs:
            # 返回根证书（通常是最后一个）
            return certs[-1]

    # 查找 PEM 格式证书
    start = body.find(b"-----BEGIN CERTIFICATE-----")
    if start >= 0:
        end = body.find(b"-----END CERTIFICATE-----")
        if end >= 0:
            end += len(b"-----END CERTIFICATE-----")
            cert_pem = body[start:end]
            try:
                return x509.load_pem_x509_certificate(cert_pem, default_backend())
            except Exception:
                pass

    # 尝试作为 DER 格式解析
    if len(body) > 100 and b"-----BEGIN" not in body:
        try:
            return x509.load_der_x509_certificate(body, default_backend())
        except Exception:
            pass

    return None


def _parse_pkcs7(data):
    """解析 PKCS#7 格式，返回证书列表"""
    try:
        # 尝试 PEM 格式
        if b"-----BEGIN" in data:
            certs = pkcs7.load_pem_pkcs7_certificates(data)
            if certs:
                return certs
        # 尝试 DER 格式
        certs = pkcs7.load_der_pkcs7_certificates(data)
        return certs if certs else []
    except Exception:
        return []


def _is_weak_cipher(cipher_suite):
    """
    判断加密套件是否为弱加密。

    弱加密特征：无前向保密(CBC模式) 或 使用不安全算法(RC4/3DES/MD5)
    """
    if not cipher_suite:
        return False
    upper = cipher_suite.upper()
    # 无前向保密：纯RSA密钥交换且为CBC模式
    # 有前向保密的前缀：ECDHE, DHE, RSA-PSK, DHE-PSK
    has_fs = any(p in upper for p in ["ECDHE-", "DHE-", "RSA-PSK", "DHE-PSK", "ECDHE-ECDSA"])
    if not has_fs:
        # 无前向保密的CBC模式套件均为弱加密
        if "CBC" in upper or "-SHA" in upper and "GCM" not in upper and "CHACHA" not in upper:
            return True
    # 不安全算法
    weak_algos = ["RC4", "DES-", "SEED", "IDEA", "MD5"]
    return any(a in upper for a in weak_algos)


def _get_key_exchange_method(cipher_suite):
    """
    从加密套件名称中提取密钥交换方法。

    返回值可能是: ECDHE, DHE, RSA, PSK, Unknown
    """
    if not cipher_suite:
        return ""
    cipher_upper = cipher_suite.upper()
    if "ECDHE" in cipher_upper or "ECHDE" in cipher_upper:
        return "ECDHE"
    elif "DHE" in cipher_upper or "EDH" in cipher_upper:
        return "DHE"
    elif "RSA" in cipher_upper:
        return "RSA"
    elif "PSK" in cipher_upper:
        return "PSK"
    else:
        return "RSA"
