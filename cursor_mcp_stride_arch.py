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

HEXAGONAL_HINTS = {"domain", "application", "app", "usecase", "use_case", "ports", "port", "adapters", "adapter", "infrastructure", "infra"}
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

    # STRIDE heurístico (mensagens)
    if not auth_present: S.append("Ausência de autenticação/guardas visíveis.")
    if jwt_usage and re.search(r"jwt\.(decode|verify)\(.*verify=False", bigtxt, re.I):
        S.append("JWT sendo decodificado sem verificação adequada.")
    if re.search(r"\bsubprocess\.(Popen|run)\(.*\+", bigtxt):
        T.append("Possível Command Injection (subprocess com concatenação).")
    if re.search(r"\bexecute\(.+[%]\s*\(", bigtxt) or "text(" in bigtxt:
        T.append("Possível SQL dinâmico sem bind parameters.")
    if "yaml.load(" in bigtxt and "SafeLoader" not in bigtxt:
        T.append("YAML load inseguro (use SafeLoader).")
    if "pickle.loads(" in bigtxt or "marshal.loads(" in bigtxt:
        T.append("Desserialização insegura.")
    if "logging" not in bigtxt.lower():
        R.append("Poucos sinais de auditoria/logs estruturados.")
    if not re.search(r"(trace_id|correlation)", bigtxt, re.I):
        R.append("Sem correlação de requisições (trace_id).")
    if debug_exposed: I.append("Debug ligado em produção (leak de stacktrace/config).")
    if cors_overly:  I.append("CORS permissivo (origem '*').")
    if re.search(r"print\(.+password|secret", bigtxt, re.I):
        I.append("Logs podem conter segredos/credenciais.")
    if re.search(r"DirectoryIndex On", bigtxt, re.I):
        I.append("Listagem de diretório habilitada.")
    if re.search(r"re\.compile\(.+\)\.match\(.+user", bigtxt, re.I):
        D.append("Regex pesada com input do usuário (risco ReDoS).")
    if re.search(r"upload.*max.?size", bigtxt, re.I) is None and uploads:
        D.append("Uploads sem limite de tamanho/validação de tipo.")
    if "while True" in bigtxt and "sleep(" not in bigtxt:
        D.append("Loops sem controle/backoff podem causar DoS.")
    if auth_present and not re.search(r"(role|permission|authorize|acl)", bigtxt, re.I):
        E.append("Auth presente, mas sem evidência de autorização fina (RBAC/ABAC).")
    if re.search(r"sudo ", bigtxt):
        E.append("Uso de sudo em automações/scripts da app.")

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

def mermaid_flow(endpoints: List[Endpoint], arch: ArchGuess) -> str:
    """
    Usa 'graph TD'; sem 'note over'. Cria nó de nota 'N0' e liga ao 'GW' com linha pontilhada.
    Evita acentos no título do subgraph para compatibilidade.
    """
    lines = []
    lines.append("```mermaid")
    lines.append("graph TD")
    lines.append("classDef note fill:#fff,stroke:#999,color:#333;")
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
            lines.append(f'        GW --> E{i}["{endpoint_text}"]')
            lines.append(f'        E{i} --> H{i}["Handler{det}"]')
            lines.append(f'        H{i} --> S{i}["Servico"]')
            lines.append(f'        S{i} --> D{i}["Repositorio/DB"]')
    else:
        lines.append("        GW --> E0[Sem rotas detectadas]")
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
        lines.append("    GW -.-> N0")
    lines.append("```")
    return "\n".join(lines)

def mermaid_sequence(endpoints: List[Endpoint]) -> str:
    lines = []
    lines.append("```mermaid")
    lines.append("sequenceDiagram")
    lines.append("    participant C as Cliente")
    lines.append("    participant R as Router")
    lines.append("    participant H as Handler")
    lines.append("    participant S as Servico")
    lines.append("    participant D as Repositorio/DB")
    if endpoints:
        for e in endpoints[:12]:  # limite p/ legibilidade
            lbl = f"{e.method} {m_escape(e.path)}"
            lines.append(f"    C->>R: {lbl}")
            lines.append("    R->>H: delega")
            lines.append("    H->>S: regra de negocio")
            lines.append("    S->>D: consulta/grava")
            lines.append("    D-->>S: resultado")
            lines.append("    S-->>H: resposta")
            lines.append("    H-->>C: HTTP 200/4xx/5xx")
    else:
        lines.append("    C->>R: (sem rotas detectadas)")
        lines.append("    R-->>C: 204 No Content")
    lines.append("```")
    return "\n".join(lines)

def _generate_diagrams_md(endpoints: List[Endpoint], arch: ArchGuess) -> str:
    flow = mermaid_flow(endpoints, arch)
    seq  = mermaid_sequence(endpoints)
    md = [
        "## Diagramas",
        "### Fluxo (graph TD)",
        flow,
        "### Sequência (sequenceDiagram)",
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
    if arch.is_microservices: bullets_arch.append("Arquitetura de **microserviços** detectada.")
    if arch.is_hexagonal: bullets_arch.append("Sinais de **Arquitetura Hexagonal (Ports & Adapters)**.")
    if arch.is_clean_layered: bullets_arch.append("Sinais de **Camadas/Clean Architecture**.")
    if arch.is_monolith: bullets_arch.append("Provável **monólito**.")
    if arch.drivers: bullets_arch.append("Frameworks: " + ", ".join(arch.drivers))
    if arch.data_stores: bullets_arch.append("Dados: " + ", ".join(arch.data_stores))
    if arch.message_brokers: bullets_arch.append("Mensageria: " + ", ".join(arch.message_brokers))
    if arch.infra_signals: bullets_arch.append("Infra: " + ", ".join(arch.infra_signals))

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
    md_parts.append("## Resumo Arquitetural")
    md_parts.extend([f"- {b}" for b in bullets_arch] or ["- (sem sinais fortes)"])

    md_parts.append("\n## Controles/Sinais de Segurança")
    if bullets_sec:
        md_parts.extend([f"- {b}" for b in bullets_sec])
    else:
        md_parts.append("- (não encontramos controles claros)")

    # Endpoints — TODOS
    md_parts.append("\n## Endpoints (todos)")
    if endpoints:
        md_parts.append("| Método | Path | Framework | Handler | Linguagem | Arquivo |")
        md_parts.append("|--------|------|-----------|---------|-----------|---------|")
        for e in endpoints:
            fw = e.framework or ""
            handler = f"`{e.handler}`" if e.handler else ""
            lang = e.language or ""
            md_parts.append(f"| {e.method} | {e.path} | {fw} | {handler} | {lang} | `{e.file}` |")
    else:
        md_parts.append("- (nenhum endpoint detectado)")

    # STRIDE – Tabela (sem contagem)
    md_parts.append("\n## STRIDE – Tabela de vulnerabilidades")
    md_parts.append("| Categoria | Vulnerabilidade |")
    md_parts.append("|-----------|------------------|")
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

    # Diagramas
    md_parts.append("")
    md_parts.append(_generate_diagrams_md(endpoints, arch))

    # JSON completo
    md_parts.append("\n---\n")
    md_parts.append("```json")
    md_parts.append(json_str)
    md_parts.append("```")

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
