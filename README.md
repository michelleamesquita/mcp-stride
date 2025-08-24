# mcp-stride# stride-arch-sketcher (MCP para Cursor)

Servidor **MCP local** em Python para o **Cursor** que:
- Analisa um repositório local (Python, JS/TS, Java, Go e **NestJS**);
- Extrai rotas/handlers e tenta inferir o estilo arquitetural (Hexagonal, Layered/Clean, Microserviços x Monólito);
- Identifica sinais de segurança (CORS, CSRF, HSTS, JWT, debug, segredos, uploads, chamadas externas);
- Gera **diagramas Mermaid** (flowchart + sequence) em **Markdown**.

## Requisitos

- **Python 3.10+**
- Cursor instalado
- (Opcional) Um arquivo `.cursor/mcp.json` no projeto — ou um `~/.cursor/mcp.json` global.

````
cat << 'EOF' > ~/.cursor/mcp.json
{               
  "mcpServers": {
    "stride-arch-sketcher": {
      "command": "python",
      "args": ["/Users/mac/Documents/mcp-stride/cursor_mcp_stride_arch.py"]
    }
  }
}
EOF
````

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Como usar (Exemplos de prompt)

  Use a ferramenta stride-arch-sketcher.full_report com {"path": "/Users/mac/Projects/minha-api", "max_files": 100}
  Use a ferramenta stride-arch-sketcher.mermaid_diagrams com {"path": "/Users/mac/Projects/minha-api", "max_files": 100}
  Use a ferramenta stride-arch-sketcher.full_report com {"path": "/Users/mac/Projects/minha-api", "max_files": 100}