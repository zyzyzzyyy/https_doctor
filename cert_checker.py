"""
HTTPS 证书检测工具 - 核心检测逻辑（纯函数，无 GUI 依赖）
"""

import ssl
import socket
import datetime
from urllib.parse import urlparse
import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp


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
            "key_exchange": ""
        }
    }

    # 解析 URL 获取主机名和端口
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443  # 默认 HTTPS 端口 443

    try:
        # 创建 SSL 上下文，启用主机名检查和证书验证
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=certifi.where())

        # 连接到服务器并获取证书信息
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # 获取 DER 格式的证书
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der is None:
                    raise ValueError("未收到证书")

                # 获取 TLS 版本和加密套件信息
                tls_version = ssock.version()
                cipher_suite = ssock.cipher()

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
                        "status": "valid"
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
                                "status": "valid"
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
                                    "status": "valid"
                                })
                except (AttributeError, Exception):
                    pass

                # 确保至少包含服务器证书
                if not cert_chain:
                    cert_chain.append({
                        "type": "server",
                        "name": _get_cert_name(cert),
                        "status": "valid"
                    })

                # 确保至少包含服务器证书
                if not cert_chain:
                    cert_chain.append({
                        "type": "server",
                        "name": _get_cert_name(cert),
                        "status": "valid"
                    })

                # 检查证书链完整性
                # 完整链应包含服务器证书以及根 CA 或中间 CA
                has_root = any(c["type"] == "root" for c in cert_chain)
                has_intermediate = any(c["type"] == "intermediate" for c in cert_chain)
                has_server = any(c["type"] == "server" for c in cert_chain)

                result["cert_chain"] = cert_chain
                # 自签名证书没有中间证书
                if has_root:
                    result["cert_chain_complete"] = True
                elif has_intermediate:
                    result["cert_chain_complete"] = True
                else:
                    result["cert_chain_complete"] = has_server

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

                # 根据过期时间确定状态
                if expired:
                    result["status"] = "error"
                elif days_left is not None and days_left <= 30:
                    result["status"] = "warning"
                else:
                    result["status"] = "valid"

                # 检查域名匹配
                cn = _get_cn(cert)
                san_list = _get_san(cert)
                match = _verify_domain_match(host, cn, san_list)

                result["domain_match"] = {
                    "match": match,
                    "cert_cn": cn,
                    "cert_san": san_list
                }

                if not match:
                    result["status"] = "error"
                    result["error_message"] = f"域名不匹配: cert={cn}, 访问={host}"

                # 通过 OCSP 检查证书吊销状态
                revocation_result = _check_ocsp(cert, host, port)
                result["revocation"] = revocation_result

                if revocation_result["status"] == "revoked":
                    result["status"] = "error"
                    result["error_message"] = "证书已被吊销"

                # 获取 TLS 信息
                result["tls"] = {
                    "version": tls_version,
                    "cipher_suite": cipher_suite[0] if cipher_suite else "",
                    "key_exchange": _get_key_exchange_method(cipher_suite[0] if cipher_suite else "")
                }

                # 检查 TLS 版本，过旧版本标记为警告
                if tls_version in ("TLSv1", "TLSv1.1"):
                    result["status"] = "warning"
                    if not result["error_message"]:
                        result["error_message"] = f"TLS {tls_version.replace('TLSv', '1.')} 已弃用"

    except socket.gaierror as e:
        result["error_message"] = f"连接失败: 无法解析域名"
        result["status"] = "error"
    except socket.timeout:
        result["error_message"] = f"连接失败: 连接超时"
        result["status"] = "error"
    except ConnectionRefusedError:
        result["error_message"] = f"连接失败: 连接被拒绝"
        result["status"] = "error"
    except ssl.SSLCertVerificationError as e:
        result["error_message"] = f"证书验证失败: {str(e)}"
        result["status"] = "error"
    except Exception as e:
        result["error_message"] = f"检测失败: {str(e)}"
        result["status"] = "error"

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
    """
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
        if san == host:
            return True
        if san.startswith("*."):
            base_domain = san[2:]
            if host.endswith(base_domain) and host != base_domain:
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

        if ":" in issuer_host:
            ih, ip = issuer_host.split(":")
            with socket.create_connection((ih, int(ip)), timeout=5) as sock:
                sock.sendall(f"GET {issuer_path} HTTP/1.1\r\nHost: {ih}\r\nConnection: close\r\n\r\n".encode())
                response = sock.recv(65536)
        else:
            with socket.create_connection((issuer_host, 443), timeout=5) as sock:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock) as ssock:
                    ssock.sendall(f"GET {issuer_path} HTTP/1.1\r\nHost: {issuer_host}\r\nConnection: close\r\n\r\n".encode())
                    response = ssock.recv(65536)

        # 从响应中提取证书（PEM 或 DER 格式）
        if b"-----BEGIN CERTIFICATE-----" in response:
            # PEM 格式
            start = response.find(b"-----BEGIN CERTIFICATE-----")
            end = response.find(b"-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
            cert_pem = response[start:end]
            return x509.load_pem_x509_certificate(cert_pem, default_backend())
        else:
            # 尝试 DER 格式（application/pkix-cert）
            # 跳过 HTTP header
            header_end = response.find(b"\r\n\r\n")
            if header_end >= 0:
                body = response[header_end + 4:]
                if body:
                    try:
                        return x509.load_der_x509_certificate(body, default_backend())
                    except Exception:
                        pass

    except Exception:
        pass

    return None


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
    elif "RSA" in cipher_upper and "E" not in cipher_upper:
        return "RSA"
    elif "PSK" in cipher_upper:
        return "PSK"
    return "Unknown"