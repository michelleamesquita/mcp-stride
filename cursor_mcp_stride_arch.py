# cursor_mcp_stride_arch.py
# Servidor MCP local para o Cursor: analisa repositório, infere arquitetura,
# extrai rotas/handlers (Python, JS/TS, Java, Go e NestJS), identifica pontos
# de segurança e gera diagramas Mermaid (Markdown).
#
# Requisitos: Python 3.10+
# pip install mcp[server]

from __future__ import annotations
import re, json, ast, logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Iterable, List, Dict, Tuple

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("mcp-arch-sketcher")

mcp = FastMCP("stride-arch-sketcher")

# --------------------------------- MODELOS ----------------------------------------

@dataclass
class Endpoint:
    method: str
    path: str
    file: str
    handler: Optional[str] = None
    framework: Optional[str] = None
    language: Optional[str] = None

@dataclass
class SecuritySignals:
    auth_present: bool
    cors_overly_permissive: bool
    csrf_present: bool
    hsts_present: bool
    debug_exposed: bool
    jwt_usage: bool
    secrets_in_code: List[str]
    file_uploads: List[str]
    external_calls: List[str]
    notes: List[str]

@dataclass
class ArchGuess:
    is_microservices: bool
    is_hexagonal: bool
    is_clean_layered: bool
    is_monolith: bool
    drivers: List[str]
    data_stores: List[str]
    message_brokers: List[str]
    infra_signals: List[str]

@dataclass
class Evidence:
    key: str           # "auth_present","cors_overly_permissive","csrf_present","hsts_present","debug_exposed","jwt_usage","secret","upload","external_call"
    file: str
    line: int
    text: str

@dataclass
class RepoAnalysis:
    root: str
    endpoints: List[Endpoint]
    arch: ArchGuess
    security: SecuritySignals
    stride_findings: Dict[str, List[str]]
    limits_hit: bool
    limits_note: Optional[str] = None
    security_evidence: List[Evidence] = None

# ------------------------------- UTILITÁRIOS --------------------------------------

FILE_SKIP_PAT = re.compile(r"\.(min|lock|svg|png|jpg|jpeg|gif|pdf|ico|wasm|class|jar|zip|tar|gz|7z)$", re.I)

def iter_code_files(root: Path, max_files:int=15000, max_size_kb:int=8192) -> Iterable[Path]:
    count = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if FILE_SKIP_PAT.search(p.name):
            continue
        try:
            size_kb = p.stat().st_size / 1024
        except Exception:
            continue
        if size_kb > max_size_kb:
            continue
        if (
            p.suffix.lower() in {".py", ".js", ".ts", ".tsx", ".java", ".kt", ".go"} or
            p.name in {
                "requirements.txt","pyproject.toml","Pipfile","package.json","go.mod","go.sum",
                "pom.xml","build.gradle","docker-compose.yml","docker-compose.yaml","Dockerfile",
                "Chart.yaml","values.yaml","deployment.yaml","deployment.yml","kustomization.yaml",
                "urls.py",
            }
        ):
            yield p
            count += 1
            if count >= max_files:
                return

# Escape seguro para strings usadas em Mermaid (labels)
def m_escape(s: str) -> str:
    if s is None:
        return ""
    return (
        s.replace("\\", "\\\\")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', '\\"')
         .replace("|", "\\|")
    )

# --------------------------- DETECTORES DE ROTAS ----------------------------------

FASTAPI_DECOR = re.compile(r"@(?:app|router)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)", re.I)
FLASK_ROUTE_DECOR = re.compile(r"@(?:app|bp|blueprint|api)\.route\(\s*['\"]([^'\"]+)['\"][^)]*\)", re.I)
DJANGO_URLS = re.compile(r"\bpath\(\s*['\"]([^'\"]+)['\"]", re.I)

EXPRESS_ROUTE = re.compile(r"\b(?:app|router)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)", re.I)

SPRING_MAPPING = re.compile(r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*(?:\(\s*value\s*=\s*)?['\"]([^'\"]+)['\"]", re.I)

GO_GIN = re.compile(r"\b(?:r|router|group)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(\s*\"([^\"]+)\"", re.I)
GO_ECHO = re.compile(r"\be\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(\s*\"([^\"]+)\"", re.I)
GO_CHI = re.compile(r"\br\.(Get|Post|Put|Delete|Patch|Options|Head)\(\s*\"([^\"]+)\"", re.I)
GO_NETHTTP = re.compile(r"\bhttp\.HandleFunc\(\s*\"([^\"]+)\"", re.I)

NEST_CONTROLLER = re.compile(r"@Controller\(\s*['\"]?([^'\"\)]*)['\"]?\s*\)", re.I)
NEST_METHOD = re.compile(r"@(Get|Post|Put|Delete|Patch|Options|Head)\(\s*['\"]?([^'\"\)]*)['\"]?\s*\)", re.I)

def py_extract_endpoints(text: str, file: str) -> List[Endpoint]:
    out: List[Endpoint] = []
    for m in FASTAPI_DECOR.finditer(text):
        out.append(Endpoint(m.group(1).upper(), m.group(2), file, framework="fastapi", language="python"))
    for m in FLASK_ROUTE_DECOR.finditer(text):
        out.append(Endpoint("*", m.group(1), file, framework="flask", language="python"))
    if file.endswith("urls.py"):
        for m in DJANGO_URLS.finditer(text):
            out.append(Endpoint("*", m.group(1), file, framework="django", language="python"))
    try:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for dec in node.decorator_list:
                    s = ast.get_source_segment(text, dec) or ""
                    if FASTAPI_DECOR.search(s) or FLASK_ROUTE_DECOR.search(s):
                        for e in reversed(out):
                            if e.handler is None and e.file == file:
                                e.handler = node.name
                                break
    except Exception:
        pass
    return out

def js_extract_endpoints(text: str, file: str) -> List[Endpoint]:
    out=[]
    for m in EXPRESS_ROUTE.finditer(text):
        out.append(Endpoint(m.group(1).upper(), m.group(2), file, framework="express", language="javascript"))
    # NestJS
    ctl_base = ""
    mctl = NEST_CONTROLLER.search(text)
    if mctl:
        ctl_base = mctl.group(1).strip()
    for m in NEST_METHOD.finditer(text):
        method = m.group(1).upper()
        mpath = (m.group(2) or "").strip()
        pieces = []
        if ctl_base:
            pieces.append(ctl_base.strip("/"))
        if mpath:
            pieces.append(mpath.strip("/"))
        full = "/" + "/".join([p for p in pieces if p])
        if full == "/":
            full = "/" + (ctl_base.strip("/") if ctl_base else "")
        out.append(Endpoint(method, full or "/", file, framework="nestjs", language="typescript"))
    return out

def java_extract_endpoints(text: str, file: str) -> List[Endpoint]:
    out=[]
    for m in SPRING_MAPPING.finditer(text):
        out.append(Endpoint("*", m.group(1).strip(), file, framework="spring", language="java"))
    return out

def go_extract_endpoints(text: str, file: str) -> List[Endpoint]:
    out=[]
    for m in GO_GIN.finditer(text):
        out.append(Endpoint(m.group(1).upper(), m.group(2), file, framework="gin", language="go"))
    for m in GO_ECHO.finditer(text):
        out.append(Endpoint(m.group(1).upper(), m.group(2), file, framework="echo", language="go"))
    for m in GO_CHI.finditer(text):
        out.append(Endpoint(m.group(1).upper(), m.group(2), file, framework="chi", language="go"))
    for m in GO_NETHTTP.finditer(text):
        out.append(Endpoint("*", m.group(1), file, framework="net/http", language="go"))
    return out

def extract_endpoints_for_file(p: Path, text: str) -> List[Endpoint]:
    try:
        if p.suffix == ".py":
            return py_extract_endpoints(text, str(p))
        if p.suffix in {".js", ".ts"}:
            return js_extract_endpoints(text, str(p))
        if p.suffix == ".java":
            return java_extract_endpoints(text, str(p))
        if p.suffix == ".go":
            return go_extract_endpoints(text, str(p))
        return []
    except Exception as ex:
        logging.warning("extract_endpoints_for_file error %s: %s", p, ex)
        return []

# -------------------------- HEURÍSTICAS DE ARQUITETURA -----------------------------

HEXAGONAL_HINTS = {"domain", "usecase", "use_case", "ports", "port", "adapters", "adapter"}
LAYERED_HINTS = {"controllers", "controller", "services", "service", "repositories", "repository"}
DB_HINTS = {"postgres", "mysql", "mariadb", "sqlite", "redis", "mongodb", "dynamodb"}
BROKER_HINTS = {"kafka", "rabbitmq", "sqs", "sns"}
K8S_HINTS = {"deployment.yaml", "deployment.yml", "kustomization.yaml", "Chart.yaml"}
MICROSERVICE_FILES = {"Dockerfile", "pom.xml", "package.json", "pyproject.toml", "go.mod"}

def guess_arch(root: Path, files: List[Path], texts: Dict[Path,str]) -> ArchGuess:
    drivers = []
    bigtxt = " ".join(texts.values()).lower()

    if "fastapi" in bigtxt: drivers.append("fastapi")
    if "from flask import" in bigtxt or "flask(" in bigtxt: drivers.append("flask")
    if "django" in bigtxt and "urls.py" in " ".join(map(str, files)): drivers.append("django")
    if "express" in bigtxt or "app.listen(" in bigtxt: drivers.append("express")
    if "@springbootapplication" in bigtxt or "<artifactid>spring-boot" in bigtxt: drivers.append("spring")
    if "github.com/gin-gonic/gin" in bigtxt: drivers.append("gin")
    if "github.com/labstack/echo" in bigtxt: drivers.append("echo")
    if "github.com/go-chi/chi" in bigtxt: drivers.append("chi")
    if "net/http" in bigtxt: drivers.append("net/http")
    if "@nestjs/common" in bigtxt or "nestjs" in bigtxt: drivers.append("nestjs")

    path_parts = set()
    for p in files:
        for part in p.parts:
            path_parts.add(part.lower())
    is_hex = any(h in path_parts for h in HEXAGONAL_HINTS)
    is_layered = any(h in path_parts for h in LAYERED_HINTS)

    docker_compose = any(p.name in {"docker-compose.yml", "docker-compose.yaml"} for p in files)
    multi_service_signals = 0
    if docker_compose: multi_service_signals += 1

    dockerfiles = [p for p in files if p.name == "Dockerfile"]
    if len(dockerfiles) >= 2: multi_service_signals += 1

    manifests_by_dir = {}
    for p in files:
        if p.name in MICROSERVICE_FILES and p.parent != root:
            manifests_by_dir.setdefault(p.parent, []).append(p.name)
    if len(manifests_by_dir) >= 2: multi_service_signals += 1

    is_micro = multi_service_signals >= 2
    is_monolith = not is_micro

    data_stores = [h for h in DB_HINTS if h in bigtxt]
    brokers = [h for h in BROKER_HINTS if h in bigtxt]
    infra = []
    if docker_compose: infra.append("docker-compose")
    if any(p.name in K8S_HINTS for p in files): infra.append("kubernetes")

    return ArchGuess(
        is_microservices=is_micro,
        is_hexagonal=is_hex,
        is_clean_layered=is_layered,
        is_monolith=is_monolith,
        drivers=sorted(set(drivers)),
        data_stores=sorted(set(data_stores)),
        message_brokers=sorted(set(brokers)),
        infra_signals=infra
    )

# --------------------- SINAIS DE SEGURANÇA + STRIDE (EVIDÊNCIAS) -------------------

SECRET_PAT = re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][^'\"\n]{8,}['\"]")
CORS_STAR = re.compile(r"(Access-Control-Allow-Origin|\bcors\().*[\*]", re.I)

def extract_security_and_stride(texts: Dict[Path,str]) -> Tuple[SecuritySignals, Dict[str,List[str]], List[Evidence]]:
    S,T,R,I,D,E = [],[],[],[],[],[]
    evidence: List[Evidence] = []

    def add_ev(key: str, p: Path, idx: int, line: str):
        snippet = line.strip()
        if len(snippet) > 160:
            snippet = snippet[:157] + "..."
        evidence.append(Evidence(key=key, file=str(p), line=idx+1, text=snippet))

    bigtxt = "\n".join(texts.values())

    for p, t in texts.items():
        for idx, line in enumerate(t.splitlines()):
            l = line
            if re.search(r"fastapi\.security|oauth2|flask_jwt|@PreAuthorize|spring-security|django\.contrib\.auth|Authorization", l):
                add_ev("auth_present", p, idx, l)
            if re.search(r"\bjwt\b", l, re.I):
                add_ev("jwt_usage", p, idx, l)
            if CORS_STAR.search(l):
                add_ev("cors_overly_permissive", p, idx, l)
            if re.search(r"CSRFProtect\(|csrf_exempt|django\.middleware\.csrf|DoubleSubmit", l):
                add_ev("csrf_present", p, idx, l)
            if "Strict-Transport-Security" in l:
                add_ev("hsts_present", p, idx, l)
            if re.search(r"DEBUG\s*=\s*True|app\.debug\s*=\s*True|spring\.profiles\.active\s*=\s*dev", l):
                add_ev("debug_exposed", p, idx, l)
            if SECRET_PAT.search(l):
                add_ev("secret", p, idx, l)
            if re.search(r"multipart|content-type.*multipart|upload", l, re.I):
                add_ev("upload", p, idx, l)
            if re.search(r"\brequests\.(get|post|put|delete)\(", l): add_ev("external_call", p, idx, l)
            if re.search(r"\bhttpx\.(get|post|put|delete)\(", l): add_ev("external_call", p, idx, l)
            if re.search(r"\baxios\.(get|post|put|delete)\(", l): add_ev("external_call", p, idx, l)
            if re.search(r"\bfetch\(", l): add_ev("external_call", p, idx, l)
            if re.search(r"\bhttp\.Get\(", l): add_ev("external_call", p, idx, l)

    auth_present = any(ev.key == "auth_present" for ev in evidence)
    jwt_usage = any(ev.key == "jwt_usage" for ev in evidence)
    cors_overly = any(ev.key == "cors_overly_permissive" for ev in evidence)
    csrf_present = any(ev.key == "csrf_present" for ev in evidence)
    hsts_present = any(ev.key == "hsts_present" for ev in evidence)
    debug_exposed = any(ev.key == "debug_exposed" for ev in evidence)

    secrets = [f"{Path(ev.file).name}:{ev.text}" for ev in evidence if ev.key == "secret"][:10]
    uploads = [ev.file for ev in evidence if ev.key == "upload"][:10]

    external_calls = []
    if re.search(r"\brequests\.(get|post|put|delete)\(", bigtxt): external_calls.append("python:requests")
    if re.search(r"\bhttpx\.(get|post|put|delete)\(", bigtxt): external_calls.append("python:httpx")
    if re.search(r"\baxios\.(get|post|put|delete)\(", bigtxt): external_calls.append("js:axios")
    if re.search(r"\bfetch\(", bigtxt): external_calls.append("js:fetch")
    if re.search(r"\bhttp\.Get\(", bigtxt): external_calls.append("go:http")

    # STRIDE heurístico (mensagens + evidências)
    if not auth_present:
        S.append("Ausência de autenticação/guardas visíveis.")
        add_ev("no_auth", Path(""), 0, "Nenhum mecanismo de autenticação detectado")

    if jwt_usage and re.search(r"jwt\.(decode|verify)\(.*verify=False", bigtxt, re.I):
        S.append("JWT sendo decodificado sem verificação adequada.")
        for p, t in texts.items():
            for idx, line in enumerate(t.splitlines()):
                if re.search(r"jwt\.(decode|verify)\(.*verify=False", line, re.I):
                    add_ev("jwt_no_verify", p, idx, line)

    if re.search(r"\bsubprocess\.(Popen|run)\(.*\+", bigtxt):
        T.append("Possível Command Injection (subprocess com concatenação).")
        for p, t in texts.items():
            for idx, line in enumerate(t.splitlines()):
                if re.search(r"\bsubprocess\.(Popen|run)\(.*\+", line):
                    add_ev("command_injection", p, idx, line)

    # SQL Injection e SQL dinâmico
    sql_patterns = [
        (r"\bexecute\(.+[%]\s*\(", "sql_dynamic", "SQL dinâmico sem bind parameters"),
        (r"text\(.+\+.+\)", "sql_injection", "Concatenação de strings em SQL"),
        (r"execute\(.+\+.+\)", "sql_injection", "Concatenação de strings em SQL"),
        (r"cursor\.execute\(.+\+.+\)", "sql_injection", "Concatenação de strings em SQL"),
        (r"\.query\(.+\+.+\)", "sql_injection", "Concatenação de strings em SQL"),
        (r"\.raw\(.+\+.+\)", "sql_injection", "SQL raw com concatenação")
    ]
    for pattern, key, msg in sql_patterns:
        if re.search(pattern, bigtxt, re.I):
            T.append(msg)
            for p, t in texts.items():
                for idx, line in enumerate(t.splitlines()):
                    if re.search(pattern, line, re.I):
                        add_ev(key, p, idx, line)

    if "yaml.load(" in bigtxt and "SafeLoader" not in bigtxt:
        T.append("YAML load inseguro (use SafeLoader).")
        for p, t in texts.items():
            for idx, line in enumerate(t.splitlines()):
                if "yaml.load(" in line and "SafeLoader" not in line:
                    add_ev("yaml_unsafe", p, idx, line)

    if "pickle.loads(" in bigtxt or "marshal.loads(" in bigtxt:
        T.append("Desserialização insegura.")
        for p, t in texts.items():
            for idx, line in enumerate(t.splitlines()):
                if "pickle.loads(" in line or "marshal.loads(" in line:
                    add_ev("insecure_deser", p, idx, line)

    if "logging" not in bigtxt.lower():
        R.append("Poucos sinais de auditoria/logs estruturados.")
        add_ev("no_logs", Path(""), 0, "Nenhum uso de logging estruturado detectado")

    if not re.search(r"(trace_id|correlation)", bigtxt, re.I):
        R.append("Sem correlação de requisições (trace_id).")
        add_ev("no_trace", Path(""), 0, "Nenhum uso de trace_id/correlação detectado")

    if debug_exposed:
        I.append("Debug ligado em produção (leak de stacktrace/config).")
       

    if cors_overly:
        I.append("CORS permissivo (origem '*').")
       

    # XSS e Input Validation
    xss_patterns = [
        (r"render_template\(.+\+.+\)", "xss_possible", "Template com concatenação de strings"),
        (r"\.html\(.+\)", "xss_raw_html", "Uso de .html() sem escape"),
        (r"innerHTML\s*=", "xss_raw_html", "Uso de innerHTML"),
        (r"dangerouslySetInnerHTML", "xss_raw_html", "Uso de dangerouslySetInnerHTML"),
        (r"__html__", "xss_raw_html", "Uso de __html__ sem escape"),
        (r"\.raw\(.+\)", "raw_render", "Uso de .raw() sem escape"),
        (r"safe\(.+\)", "raw_render", "Uso de |safe sem escape"),
        (r"mark_safe\(.+\)", "raw_render", "Uso de mark_safe sem escape")
    ]
    for pattern, key, msg in xss_patterns:
        if re.search(pattern, bigtxt, re.I):
            I.append(msg)
            for p, t in texts.items():
                for idx, line in enumerate(t.splitlines()):
                    if re.search(pattern, line, re.I):
                        add_ev(key, p, idx, line)

    # Input Validation
    input_patterns = [
        (r"request\.(args|form|json|data)\[.+\]", "raw_input_used", "Uso direto de input sem validação"),
        (r"request\.get_json\(\)", "raw_input_used", "JSON sem validação de schema"),
        (r"request\.files\[.+\]", "raw_input_used", "Upload sem validação de tipo"),
        (r"@app\.route.*<\w+:.*>", "no_input_validation", "Parâmetro de rota sem validação"),
        (r"params\[.+\]", "raw_input_used", "Parâmetros sem validação")
    ]
    for pattern, key, msg in input_patterns:
        if re.search(pattern, bigtxt, re.I):
            I.append(msg)
            for p, t in texts.items():
                for idx, line in enumerate(t.splitlines()):
                    if re.search(pattern, line, re.I):
                        add_ev(key, p, idx, line)

    # Rate Limiting
    rate_limit_frameworks = [
        "flask_limiter",
        "@limiter",
        "rate_limit",
        "RateLimit",
        "throttle",
        "Throttle"
    ]
    if not any(f in bigtxt for f in rate_limit_frameworks):
        I.append("Sem rate limiting detectado.")
        add_ev("no_rate_limit", Path(""), 0, "Nenhum mecanismo de rate limiting encontrado")

    # Logs com segredos
    if re.search(r"print\(.+password|secret", bigtxt, re.I):
        I.append("Logs podem conter segredos/credenciais.")
        for p, t in texts.items():
            for idx, line in enumerate(t.splitlines()):
                if re.search(r"print\(.+password|secret", line, re.I):
                    add_ev("logs_with_secrets", p, idx, line)

    if re.search(r"DirectoryIndex On", bigtxt, re.I):
        I.append("Listagem de diretório habilitada.")
        for p, t in texts.items():
            for idx, line in enumerate(t.splitlines()):
                if re.search(r"DirectoryIndex On", line, re.I):
                    add_ev("dir_listing", p, idx, line)

    if re.search(r"re\.compile\(.+\)\.match\(.+user", bigtxt, re.I):
        D.append("Regex pesada com input do usuário (risco ReDoS).")
        for p, t in texts.items():
            for idx, line in enumerate(t.splitlines()):
                if re.search(r"re\.compile\(.+\)\.match\(.+user", line, re.I):
                    add_ev("regex_redos", p, idx, line)

    if re.search(r"upload.*max.?size", bigtxt, re.I) is None and uploads:
        D.append("Uploads sem limite de tamanho/validação de tipo.")
        for p, t in texts.items():
            for idx, line in enumerate(t.splitlines()):
                if re.search(r"upload", line, re.I) and not re.search(r"max.?size", line, re.I):
                    add_ev("upload_no_size", p, idx, line)

    if "while True" in bigtxt and "sleep(" not in bigtxt:
        D.append("Loops sem controle/backoff podem causar DoS.")
        for p, t in texts.items():
            for idx, line in enumerate(t.splitlines()):
                if "while True" in line and "sleep(" not in line:
                    add_ev("busy_loop", p, idx, line)

    if auth_present and not re.search(r"(role|permission|authorize|acl)", bigtxt, re.I):
        E.append("Auth presente, mas sem evidência de autorização fina (RBAC/ABAC).")
        add_ev("no_rbac", Path(""), 0, "Autenticação presente mas sem RBAC/autorização fina")

    if re.search(r"sudo ", bigtxt):
        E.append("Uso de sudo em automações/scripts da app.")
        for p, t in texts.items():
            for idx, line in enumerate(t.splitlines()):
                if re.search(r"sudo ", line):
                    add_ev("command_injection", p, idx, line)

    security = SecuritySignals(
        auth_present=auth_present,
        cors_overly_permissive=cors_overly,
        csrf_present=csrf_present,
        hsts_present=hsts_present,
        debug_exposed=debug_exposed,
        jwt_usage=jwt_usage,
        secrets_in_code=secrets,
        file_uploads=uploads,
        external_calls=sorted(set(external_calls)),
        notes=[]
    )
    stride = {"S":S, "T":T, "R":R, "I":I, "D":D, "E":E}
    return security, stride, evidence

# ------------------------- HELPERS PARA RESUMO/REFS --------------------------------

def _index_evidence(evidence: List[Evidence]) -> Dict[str, List[Evidence]]:
    by_key: Dict[str, List[Evidence]] = {}
    for ev in (evidence or []):
        by_key.setdefault(ev.key, []).append(ev)
    return by_key

def _fmt_refs(items: List[Evidence], max_refs:int=3) -> str:
    if not items:
        return ""
    parts = [f"`{Path(ev.file).name}:{ev.line}`" for ev in items[:max_refs]]
    return " — ex.: " + "; ".join(parts)

# ----------------------------- DIAGRAMAS MERMAID -----------------------------------

def mermaid_flow(endpoints: List[Endpoint], arch: ArchGuess, stride: Dict[str,List[str]]=None, evidence: List[Evidence]=None) -> str:
    """
    Gera diagrama de fluxo Mermaid com:
    - Estrutura base da aplicação (Usuario -> Gateway -> Handler -> Servico -> DB)
    - Notas sobre arquitetura detectada
    - Vulnerabilidades STRIDE destacadas em vermelho onde impactam a arquitetura
    """
    lines = []
    lines.append("```mermaid")
    lines.append("graph TD")
    lines.append("classDef note fill:#fff,stroke:#999,color:#333;")
    lines.append("classDef vuln fill:#fff0f0,stroke:#c00,color:#333;")
    lines.append('    U[Usuário/Cliente] -->|HTTP| GW[Router/API Gateway]')
    lines.append('    subgraph App["Aplicacao / Servicos"]')
    if endpoints:
        for i, e in enumerate(endpoints[:60], start=1):  # limite para renderização
            endpoint_text = f"{e.method} {m_escape(e.path)}"
            details = []
            if e.framework: details.append(f"({m_escape(e.framework)})")
            if e.handler:   details.append(f"handler: {m_escape(e.handler)}")
            if e.language:  details.append(f"lang: {m_escape(e.language)}")
            det = "<br/>" + "<br/>".join(details) if details else ""
            lines.append(f'        Gateway --> E{i}["{endpoint_text}"]')
            lines.append(f'        E{i} --> Handler{i}["Handler{det}"]')
            lines.append(f'        Handler{i} --> Servico{i}["Servico"]')
            lines.append(f'        Servico{i} --> DB{i}["Repositorio/DB"]')
    else:
        lines.append("        Gateway --> E0[Sem rotas detectadas]")
    lines.append("    end")

    notes = []
    if arch.is_microservices: notes.append("Microservicos")
    if arch.is_hexagonal: notes.append("Hexagonal (Ports/Adapters)")
    if arch.is_clean_layered: notes.append("Layered/Clean")
    if arch.infra_signals: notes.append("Infra: " + ", ".join(arch.infra_signals))
    if arch.data_stores: notes.append("Dados: " + ", ".join(arch.data_stores))
    if arch.message_brokers: notes.append("Mensageria: " + ", ".join(arch.message_brokers))
    if notes:
        note_text = "<br/>".join(notes).replace('"', '\\"')
        lines.append(f'    N0["{note_text}"]:::note')
        lines.append("    Gateway -.-> N0")
    
    # Adicionar nós de vulnerabilidade STRIDE se fornecidos
    if stride and evidence:
        # Spoofing (autenticação)
        if any(ev.key == "no_auth" for ev in evidence):
            lines.append('    V1[Sem autenticacao]:::vuln')
            lines.append('    Usuario --> V1')
            lines.append('    V1 --> Gateway')
        
        # Tampering (injeções)
        sql_vuln = any(ev.key in {"sql_injection", "sql_dynamic"} for ev in evidence)
        if sql_vuln:
            lines.append('    V2[SQL Injection]:::vuln')
            lines.append('    Servico --> V2')
            lines.append('    V2 --> DB')
        
        cmd_vuln = any(ev.key == "command_injection" for ev in evidence)
        if cmd_vuln:
            lines.append('    V3[Command Injection]:::vuln')
            lines.append('    Servico --> V3')
        
        # Repudiation (logs)
        if any(ev.key in {"no_logs", "no_trace"} for ev in evidence):
            lines.append('    V4[Sem logs/trace]:::vuln')
            lines.append('    Handler --> V4')
        
        # Information Disclosure
        if any(ev.key in {"cors_overly_permissive", "debug_exposed"} for ev in evidence):
            lines.append('    V5[CORS * / Debug]:::vuln')
            lines.append('    Gateway --> V5')
        
        if any(ev.key in {"secret", "logs_with_secrets"} for ev in evidence):
            lines.append('    V6[Segredos expostos]:::vuln')
            lines.append('    Servico --> V6')
        
        # Denial of Service
        if any(ev.key in {"busy_loop", "regex_redos", "upload_no_size"} for ev in evidence):
            lines.append('    V7[DoS: loops/regex/upload]:::vuln')
            lines.append('    Handler --> V7')
        
        # Elevation of Privilege
        if any(ev.key == "no_rbac" for ev in evidence):
            lines.append('    V8[Sem RBAC]:::vuln')
            lines.append('    Handler --> V8')
    
    lines.append("```")
    return "\n".join(lines)

def mermaid_sequence(endpoints: List[Endpoint]) -> str:
    """
    Gera diagrama de sequência Mermaid mostrando o fluxo de chamadas para cada endpoint:
    Cliente -> Router -> Handler -> Servico -> DB
    """
    lines = []
    lines.append("```mermaid")
    lines.append("sequenceDiagram")
    lines.append("    participant Cliente")
    lines.append("    participant Router")
    lines.append("    participant Handler")
    lines.append("    participant Servico")
    lines.append("    participant DB as Repositorio/DB")
    if endpoints:
        for e in endpoints[:12]:  # limite p/ legibilidade
            lbl = f"{e.method} {m_escape(e.path)}"
            lines.append(f"    Cliente->>Router: {lbl}")
            lines.append("    Router->>Handler: delega")
            lines.append("    Handler->>Servico: regra de negocio")
            lines.append("    Servico->>DB: consulta/grava")
            lines.append("    DB-->>Servico: resultado")
            lines.append("    Servico-->>Handler: resposta")
            lines.append("    Handler-->>Cliente: HTTP 200/4xx/5xx")
    else:
        lines.append("    Cliente->>Router: (sem rotas detectadas)")
        lines.append("    Router-->>Cliente: 204 No Content")
    lines.append("```")
    return "\n".join(lines)

def _generate_diagrams_md(endpoints: List[Endpoint], arch: ArchGuess) -> str:
    flow = mermaid_flow(endpoints, arch)
    seq  = mermaid_sequence(endpoints)
    md = [
        "\n## Diagramas",
        "\n### Fluxo",
        flow,
        "\n### Sequência",
        seq
    ]
    return "\n".join(md)

# --------------------------------- MCP TOOLS ---------------------------------------

def load_repo_texts(path: str, max_files:int=15000, max_size_kb:int=8192) -> Tuple[Path, List[Path], Dict[Path,str]]:
    root = Path(path).resolve()
    files = list(iter_code_files(root, max_files=max_files, max_size_kb=max_size_kb))
    texts: Dict[Path,str] = {}
    for p in files:
        try:
            texts[p] = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
    return root, files, texts

@mcp.tool()
async def analyze_repo(path: str = ".", max_files:int=15000, max_size_kb:int=8192) -> str:
    """
    Analisa um repositório local e retorna:
    - Um RESUMO em Markdown (arquitetura, segurança com refs de arquivo:linha, TODOS os endpoints, STRIDE em tabela, diagramas);
    - Em seguida, o JSON completo (formatado) com os mesmos dados.
    """
    root, files, texts = load_repo_texts(path, max_files=max_files, max_size_kb=max_size_kb)
    endpoints: List[Endpoint] = []
    for p in files:
        t = texts.get(p)
        if t:
            endpoints.extend(extract_endpoints_for_file(p, t))

    arch = guess_arch(root, files, texts)
    security, stride, evidence = extract_security_and_stride(texts)
    ev_index = _index_evidence(evidence)

    limits_hit = len(files) >= max_files
    limits_note = (
        f"A análise pode ter atingido alguns limites e pode não estar completa. "
        f"Tente aumentar 'max_files' (atual {max_files}) ou 'max_size_kb' (atual {max_size_kb})."
    ) if limits_hit else None

    analysis = RepoAnalysis(
        root=str(root),
        endpoints=endpoints,
        arch=arch,
        security=security,
        stride_findings=stride,
        limits_hit=limits_hit,
        limits_note=limits_note,
        security_evidence=evidence
    )

    # ---------- JSON ----------
    out = asdict(analysis)
    out["endpoints"] = [asdict(e) for e in endpoints]
    out["arch"] = asdict(arch)
    out["security"] = asdict(security)
    out["security_evidence"] = [asdict(ev) for ev in (evidence or [])]
    json_str = json.dumps(out, indent=2, ensure_ascii=False)

    # ---------- RESUMO ----------
    bullets_arch = []
    
    # Arquitetura
    if arch.is_microservices:
        evidencias = []
        if any(p.name == "docker-compose.yml" or p.name == "docker-compose.yaml" for p in files):
            file = next(p for p in files if p.name in {"docker-compose.yml", "docker-compose.yaml"})
            evidencias.append(f"[{file.name}:1]({file}#1)")
        if len([p for p in files if p.name == "Dockerfile"]) >= 2:
            dockerfiles = [p for p in files if p.name == "Dockerfile"]
            evidencias.extend(f"[{p.parent.name}/Dockerfile:1]({p}#1)" for p in dockerfiles[:3])
        bullets_arch.append("🏗️ Arquitetura de **microserviços** detectada" + (" — " + ", ".join(evidencias) if evidencias else ""))
    
    if arch.is_hexagonal:
        evidencias = []
        for p in files:
            for part in p.parts:
                if part.lower() in HEXAGONAL_HINTS:
                    evidencias.append(f"[{p.name}:1]({p}#1)")
                    break
        bullets_arch.append("🏗️ Sinais de **Arquitetura Hexagonal (Ports & Adapters)**" + (" — " + ", ".join(evidencias[:3]) if evidencias else ""))
    
    if arch.is_clean_layered:
        evidencias = []
        for p in files:
            for part in p.parts:
                if part.lower() in LAYERED_HINTS:
                    evidencias.append(f"[{p.name}:1]({p}#1)")
                    break
        bullets_arch.append("🏗️ Sinais de **Camadas/Clean Architecture**" + (" — " + ", ".join(evidencias[:3]) if evidencias else ""))
    
    if arch.is_monolith:
        bullets_arch.append("🏗️ Provável **monólito**")
    
    # Frameworks e Tecnologias
    if arch.drivers:
        framework_evidencias = {}
        for fw in arch.drivers:
            for p, t in texts.items():
                if fw == "fastapi" and "fastapi" in t:
                    framework_evidencias[fw] = str(p)
                    break
                elif fw == "flask" and ("from flask import" in t or "flask(" in t):
                    framework_evidencias[fw] = str(p)
                    break
                elif fw == "django" and "urls.py" in str(p):
                    framework_evidencias[fw] = str(p)
                    break
                elif fw == "express" and ("express" in t or "app.listen(" in t):
                    framework_evidencias[fw] = str(p)
                    break
                elif fw == "spring" and ("@springbootapplication" in t.lower() or "<artifactid>spring-boot" in t.lower()):
                    framework_evidencias[fw] = str(p)
                    break
        
        frameworks_str = []
        for fw in arch.drivers:
            if fw in framework_evidencias:
                file_path = framework_evidencias[fw]
                file_name = Path(file_path).name
                frameworks_str.append(f"{fw} ([{file_name}:1]({file_path}#L1))")
            else:
                frameworks_str.append(fw)
        bullets_arch.append("⚙️ Frameworks: " + ", ".join(frameworks_str))
    
    # Dados e Mensageria
    if arch.data_stores:
        db_evidencias = {}
        for db in arch.data_stores:
            for p, t in texts.items():
                if db in t.lower():
                    db_evidencias[db] = str(p)
                    break
        dbs_str = []
        for db in arch.data_stores:
            if db in db_evidencias:
                file_path = db_evidencias[db]
                file_name = Path(file_path).name
                dbs_str.append(f"{db} ([{file_name}:1]({file_path}#L1))")
            else:
                dbs_str.append(db)
        bullets_arch.append("💾 Bancos de dados: " + ", ".join(dbs_str))
    
    if arch.message_brokers:
        broker_evidencias = {}
        for broker in arch.message_brokers:
            for p, t in texts.items():
                if broker in t.lower():
                    broker_evidencias[broker] = str(p)
                    break
        brokers_str = []
        for broker in arch.message_brokers:
            if broker in broker_evidencias:
                file_path = broker_evidencias[broker]
                file_name = Path(file_path).name
                brokers_str.append(f"{broker} ([{file_name}:1]({file_path}#L1))")
            else:
                brokers_str.append(broker)
        bullets_arch.append("📨 Mensageria: " + ", ".join(brokers_str))
    
    # Infraestrutura
    if arch.infra_signals:
        infra_evidencias = {}
        for infra in arch.infra_signals:
            if infra == "docker-compose":
                file = next((p for p in files if p.name in {"docker-compose.yml", "docker-compose.yaml"}), None)
                if file:
                    infra_evidencias[infra] = str(file)
            elif infra == "kubernetes":
                file = next((p for p in files if p.name in K8S_HINTS), None)
                if file:
                    infra_evidencias[infra] = str(file)
        
        infra_str = []
        for infra in arch.infra_signals:
            if infra in infra_evidencias:
                file_path = infra_evidencias[infra]
                file_name = Path(file_path).name
                infra_str.append(f"{infra} ([{file_name}:1]({file_path}#L1))")
            else:
                infra_str.append(infra)
        bullets_arch.append("🚀 Infraestrutura: " + ", ".join(infra_str))
    
    # Endpoints e Rotas
    total_endpoints = len(endpoints)
    frameworks_count = {}
    methods_count = {}
    handlers_count = 0
    for e in endpoints:
        if e.framework:
            frameworks_count[e.framework] = frameworks_count.get(e.framework, 0) + 1
        methods_count[e.method] = methods_count.get(e.method, 0) + 1
        if e.handler:
            handlers_count += 1
    
    if total_endpoints > 0:
        bullets_arch.append(f"\n**{total_endpoints} endpoints** detectados:")
        # Contagem por framework
        for fw, count in frameworks_count.items():
            bullets_arch.append(f"  - {count} rotas em {fw}")
        # Contagem por método HTTP
        methods_summary = [f"{count} {method}" for method, count in methods_count.items()]
        bullets_arch.append(f"  - Métodos HTTP: {', '.join(methods_summary)}")
        # Handlers
        bullets_arch.append(f"  - {handlers_count} handlers implementados")

    # Map controles -> evidências (arquivo:linha)
    ev_map = {
        "Autenticação detectada.":              ev_index.get("auth_present", []),
        "CSRF presente.":                       ev_index.get("csrf_present", []),
        "HSTS presente.":                       ev_index.get("hsts_present", []),
        "⚠️ CORS permissivo ('*').":            ev_index.get("cors_overly_permissive", []),
        "⚠️ Debug possivelmente habilitado.":   ev_index.get("debug_exposed", []),
        "Uso de JWT detectado.":                ev_index.get("jwt_usage", []),
        "⚠️ Possíveis segredos em código (amostras).": ev_index.get("secret", []),
        "Uploads detectados.":                  ev_index.get("upload", []),
        "Chamadas externas detectadas.":        ev_index.get("external_call", []),
    }

    bullets_sec: List[str] = []
    if security.auth_present: bullets_sec.append("Autenticação detectada." + _fmt_refs(ev_map["Autenticação detectada."]))
    if security.csrf_present: bullets_sec.append("CSRF presente." + _fmt_refs(ev_map["CSRF presente."]))
    if security.hsts_present: bullets_sec.append("HSTS presente." + _fmt_refs(ev_map["HSTS presente."]))
    if security.cors_overly_permissive: bullets_sec.append("⚠️ CORS permissivo ('*')." + _fmt_refs(ev_map["⚠️ CORS permissivo ('*')."]))
    if security.debug_exposed: bullets_sec.append("⚠️ Debug possivelmente habilitado." + _fmt_refs(ev_map["⚠️ Debug possivelmente habilitado."]))
    if security.jwt_usage: bullets_sec.append("Uso de JWT detectado." + _fmt_refs(ev_map["Uso de JWT detectado."]))
    if security.secrets_in_code: bullets_sec.append("⚠️ Possíveis segredos em código (amostras)." + _fmt_refs(ev_map["⚠️ Possíveis segredos em código (amostras)."]))
    if ev_map["Uploads detectados."]: bullets_sec.append("Uploads detectados." + _fmt_refs(ev_map["Uploads detectados."]))
    if ev_map["Chamadas externas detectadas."]:
        extra = " Tipos: " + ", ".join(security.external_calls) if security.external_calls else ""
        bullets_sec.append("Chamadas externas detectadas." + _fmt_refs(ev_map["Chamadas externas detectadas."]) + extra)

    # ---------- Markdown final ----------
    md_parts = []
    md_parts.append(f"# Análise de Repositório – {analysis.root}")
    if limits_note:
        md_parts.append(f"> **Nota:** {limits_note}")

    # Resumo arquitetural
    md_parts.append("## Resumo Arquitetural")
    md_parts.extend([f"- {b}" for b in bullets_arch] or ["- (sem sinais fortes)"])

    # Lista completa de endpoints
    if endpoints:
        md_parts.append("\n## Endpoints Detectados")
        
        # Agrupar por framework
        by_framework = {}
        for e in endpoints:
            fw = e.framework or "outros"
            by_framework.setdefault(fw, []).append(e)
        
        # Listar por framework
        for fw, eps in sorted(by_framework.items()):
            md_parts.append(f"\n### {fw.title()}")
            md_parts.append("| Método | Path | Handler | Arquivo:linha |")
            md_parts.append("|--------|------|---------|---------------|")
            for e in sorted(eps, key=lambda x: (x.path, x.method)):
                # Criar link clicável para o arquivo
                file_path = str(Path(e.file).resolve()).replace("\\", "/")
                file_name = Path(e.file).name
                handler = e.handler if e.handler else "-"
                # Procurar a linha real do endpoint
                line = 1
                if e.file in texts:
                    text = texts[e.file]
                    lines = text.splitlines()
                    # Primeiro tenta encontrar o decorador/definição exata
                    for i, line_text in enumerate(lines, 1):
                        if any([
                            # Python (FastAPI, Flask)
                            f"@app.{e.method.lower()}('{e.path}')" in line_text,
                            f'@app.{e.method.lower()}("{e.path}")' in line_text,
                            f"@app.route('{e.path}')" in line_text,
                            f'@app.route("{e.path}")' in line_text,
                            f"@app.route('{e.path}', methods=[" in line_text,
                            f'@app.route("{e.path}", methods=[' in line_text,
                            # Express.js
                            f"app.{e.method.lower()}('{e.path}'," in line_text,
                            f'app.{e.method.lower()}("{e.path}",' in line_text,
                            f"router.{e.method.lower()}('{e.path}'," in line_text,
                            f'router.{e.method.lower()}("{e.path}",' in line_text,
                            # Spring
                            f"@RequestMapping('{e.path}')" in line_text,
                            f'@RequestMapping("{e.path}")' in line_text,
                            f"@{e.method.capitalize()}Mapping('{e.path}')" in line_text,
                            f'@{e.method.capitalize()}Mapping("{e.path}")' in line_text,
                            # Django
                            f"path('{e.path}'," in line_text,
                            f'path("{e.path}",' in line_text,
                            f"url(r'^{e.path}'," in line_text,
                            f'url(r"{e.path}",' in line_text,
                        ]):
                            line = i
                            break
                    
                    # Se não encontrou, procura por padrões mais genéricos
                    if line == 1:
                        for i, line_text in enumerate(lines, 1):
                            if any([
                                # Decoradores Python
                                f"@app.route('{e.path}" in line_text,
                                f'@app.route("{e.path}' in line_text,
                                f"@app.{e.method.lower()}('{e.path}" in line_text,
                                f'@app.{e.method.lower()}("{e.path}' in line_text,
                                # Express/Node
                                f"app.{e.method.lower()}('{e.path}" in line_text,
                                f'app.{e.method.lower()}("{e.path}' in line_text,
                                f"router.{e.method.lower()}('{e.path}" in line_text,
                                f'router.{e.method.lower()}("{e.path}' in line_text,
                                # Django
                                f"path('{e.path}" in line_text,
                                f'path("{e.path}' in line_text,
                            ]):
                                line = i
                                break
                    
                    # Se ainda não encontrou, procura pelo path em qualquer lugar
                    if line == 1:
                        for i, line_text in enumerate(lines, 1):
                            if e.path in line_text and (e.method == "*" or e.method.lower() in line_text.lower()):
                                line = i
                                break
                md_parts.append(f"| {e.method} | `{e.path}` | `{handler}` | [{file_name}:{line}]({file_path}#L{line}) |")

    # === SEGURANÇA (Controles + Vulnerabilidades) ===
    md_parts.append("\n## Segurança")
    
    # Indexar evidências por tipo
    by_key = _index_evidence(evidence)
    
    # Separar em controles vs vulnerabilidades
    controls = {
        "auth_present": "Auth (informativo)",
        "csrf_present": "CSRF (informativo)",
        "hsts_present": "HSTS (informativo)",
        "jwt_usage": "JWT (informativo)",
        "upload": "Upload/Multi-part"
    }

    # Primeiro os controles
    md_parts.append("\n### 🔒 Controles de Segurança Detectados")
    control_keys = list(controls.keys())
    has_controls = any(by_key.get(k) for k in control_keys)
    if has_controls:
        md_parts.append("| Tipo | Arquivo:linha | Trecho |")
        md_parts.append("|------|---------------|--------|")
        for k in control_keys:
            for ev in by_key.get(k, []):
                # Limitar o tamanho do snippet e escapar caracteres especiais
                snippet = (ev.text or "").strip()
                if len(snippet) > 80:  # Reduzir ainda mais o tamanho máximo do snippet
                    snippet = snippet[:77] + "..."
                # Escapar caracteres especiais e remover quebras de linha
                snippet = (
                    snippet.replace("\\", "\\\\")
                            .replace("|", "\\|")
                            .replace("\n", " ")
                            .replace("\r", "")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                )
                
                # Criar link clicável para o arquivo:linha
                file_path = str(Path(ev.file).resolve()).replace("\\", "/")
                file_name = Path(ev.file).name
                md_parts.append(f"| {controls.get(k, k)} | [{file_name}:{ev.line}]({file_path}#L{ev.line}) | `{snippet}` |")
    else:
        md_parts.append("- (nenhum controle de segurança detectado)")

    # Depois as vulnerabilidades
    vulns = {
        "cors_overly_permissive": "⚠️ CORS permissivo",
        "debug_exposed": "⚠️ Debug exposto",
        "secret": "⚠️ Segredo em código",
        "command_injection": "⚠️ Command Injection",
        "sql_dynamic": "⚠️ SQL dinâmico sem bind parameters",
        "sql_injection": "⚠️ SQL Injection possível",
        "yaml_unsafe": "⚠️ YAML load inseguro",
        "insecure_deser": "⚠️ Desserialização insegura",
        "logs_leak": "⚠️ Logs com segredos",
        "dir_listing": "⚠️ Listagem de diretório",
        "regex_redos": "⚠️ Regex pesada/ReDoS",
        "busy_loop": "⚠️ Loop sem backoff",
        "jwt_no_verify": "⚠️ JWT sem verificação",
        "external_call": "⚠️ Chamada externa",
        "upload_no_size": "⚠️ Upload sem limite de tamanho",
        "logs_with_secrets": "⚠️ Logs podem conter segredos",
        "no_auth": "⚠️ Ausência de autenticação",
        "no_rbac": "⚠️ Sem RBAC/autorização fina",
        "no_logs": "⚠️ Sem logs estruturados",
        "no_trace": "⚠️ Sem trace_id/correlação",
        "xss_possible": "⚠️ XSS possível (sem escape)",
        "xss_raw_html": "⚠️ XSS via raw HTML/innerHTML",
        "no_input_validation": "⚠️ Sem validação de input",
        "no_rate_limit": "⚠️ Sem rate limiting",
        "no_input_sanitization": "⚠️ Sem sanitização de input",
        "raw_input_used": "⚠️ Input usado sem tratamento",
        "raw_render": "⚠️ Renderização direta de input"
    }
    
    # Vulnerabilidades
    md_parts.append("\n### 🛑 Vulnerabilidades Detectadas")
    vuln_keys = list(vulns.keys())
    has_vulns = any(by_key.get(k) for k in vuln_keys)
    if has_vulns:
        md_parts.append("| Tipo | Arquivo:linha | Trecho |")
        md_parts.append("|------|---------------|--------|")
        for k in vuln_keys:
            for ev in by_key.get(k, []):
                # Limitar o tamanho do snippet e escapar caracteres especiais
                snippet = (ev.text or "").strip()
                if len(snippet) > 80:  # Reduzir ainda mais o tamanho máximo do snippet
                    snippet = snippet[:77] + "..."
                # Escapar caracteres especiais e remover quebras de linha
                snippet = (
                    snippet.replace("\\", "\\\\")
                            .replace("|", "\\|")
                            .replace("\n", " ")
                            .replace("\r", "")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                )
                
                # Criar link clicável para o arquivo:linha
                file_path = str(Path(ev.file).resolve()).replace("\\", "/")
                file_name = Path(ev.file).name
                md_parts.append(f"| {vulns.get(k, k)} | [{file_name}:{ev.line}]({file_path}#L{ev.line}) | `{snippet}` |")
    else:
        md_parts.append("- (nenhuma vulnerabilidade detectada)")

    if not has_controls and not has_vulns:
        md_parts.append("- (nenhum ponto de interesse ou vulnerabilidade detectada)")

    # STRIDE – Tabela (sem contagem)
    md_parts.append("\n## STRIDE – Tabela de vulnerabilidades")
    md_parts.append("| Categoria | Vulnerabilidade |")
    md_parts.append("|:----------|:-----------------|")
    label = {
        "S": "Spoofing",
        "T": "Tampering",
        "R": "Repudiation",
        "I": "Information Disclosure",
        "D": "Denial of Service",
        "E": "Elevation of Privilege",
    }
    for k in ["S","T","R","I","D","E"]:
        items = (stride.get(k) or [])
        if not items:
            md_parts.append(f"| {label[k]} | (sem achados) |")
        else:
            for msg in items:
                safe = msg.replace("|","\\|")
                md_parts.append(f"| {label[k]} | {safe} |")

    # Diagramas Mermaid (mantidos)
    md_parts.append("")
    md_parts.append(_generate_diagrams_md(endpoints, arch))

    # Adicionar vulnerabilidades STRIDE ao diagrama de fluxo
    flow_with_stride = mermaid_flow(endpoints, arch, stride, evidence)
    md_parts[-1] = md_parts[-1].replace(mermaid_flow(endpoints, arch), flow_with_stride)

    return "\n".join(md_parts)



@mcp.tool()
async def mermaid_diagrams(path: str = ".", max_files:int=15000, max_size_kb:int=8192) -> str:
    """Retorna apenas os dois diagramas Mermaid (flow e sequence), em Markdown."""
    root, files, texts = load_repo_texts(path, max_files=max_files, max_size_kb=max_size_kb)
    endpoints: List[Endpoint] = []
    for p in files:
        t = texts.get(p)
        if t:
            endpoints.extend(extract_endpoints_for_file(p, t))
    arch = guess_arch(root, files, texts)
    return _generate_diagrams_md(endpoints, arch)

@mcp.tool()
async def full_report(path: str = ".", max_files:int=15000, max_size_kb:int=8192) -> str:
    """
    Relatório completo (Markdown) com resumo arquitetural, segurança, endpoints, STRIDE em tabela, diagramas e evidências em JSON.
    (Sem seção de contagem STRIDE.)
    """
    return await analyze_repo(path=path, max_files=max_files, max_size_kb=max_size_kb)

if __name__ == "__main__":
    mcp.run(transport="stdio")
