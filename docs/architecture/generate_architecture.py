"""Generate source-backed architecture pages without starting project services.

Requires PyYAML and the installed drawio-skill. Only explicitly selected,
non-secret Compose fields are retained in the model.
"""
from __future__ import annotations

import html
import importlib.util
import json
from pathlib import Path
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET

import yaml

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
SKILL = Path.home() / ".codex/skills/drawio-skill"
sys.path.insert(0, str(SKILL / "scripts"))
import composeimports  # noqa: E402

WIDTH, HEIGHT = 1600, 1120
PALETTE = json.loads((SKILL / "styles/built-in/default.json").read_text("utf-8"))["palette"]
FONT = "Malgun Gothic"
NODES, EDGES, VIEWS = {}, [], []


def wrap_label(text, width, size):
    result = []
    for paragraph in text.splitlines():
        line, used = "", 0
        for token in re.findall(r"\S+\s*", paragraph):
            advance = sum(size * (1 if unicodedata.east_asian_width(char) in "WF" else .57) for char in token)
            if line and used + advance > width:
                result.append(line.rstrip())
                line, used = "", 0
            line += token
            used += advance
        result.append(line)
    return "\n".join(result)


def evidence(path, fragment):
    lines = (ROOT / path).read_text("utf-8").splitlines()
    return {"path": path, "line": next(i for i, line in enumerate(lines, 1) if fragment in line)}


def model_node(key, label, kind="service", provenance=None, **properties):
    NODES.setdefault(key, {"id": key, "label": label, "kind": kind,
                          "properties": properties, "provenance": provenance or {}})


compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text("utf-8"))
for name, service in compose["services"].items():
    networks = list(service.get("networks", []))
    model_node(name, name, provenance=evidence("docker-compose.yml", f"  {name}:"),
               networks=networks, network_mode=service.get("network_mode"),
               published_ports=service.get("ports", []),
               container_name=service.get("container_name"),
               image=service.get("image"), build=service.get("build"),
               runtime_status="stopped per user context; not independently inspected"
               if name == "remediation" else "not inspected")
    for dep in composeimports.dependencies(service):
        EDGES.append({"id": f"dependency:{name}:{dep}", "source": name, "target": dep,
                      "kind": "dependency", "label": "depends_on (startup)",
                      "provenance": evidence("docker-compose.yml", f"  {name}:")})
    for vol in composeimports.volume_mounts(service):
        if vol in compose["volumes"]:
            model_node(f"vol:{vol}", vol, "database", evidence("docker-compose.yml", f"  {vol}:"))
            EDGES.append({"id": f"mount:{name}:{vol}", "source": name, "target": f"vol:{vol}",
                          "kind": "mount", "label": "volume mount"})


class Page:
    def __init__(self, pid, name, title, subtitle):
        self.id, self.name = pid, name
        self.diagram = ET.Element("diagram", {"id": pid, "name": name})
        self.graph = ET.SubElement(self.diagram, "mxGraphModel", {
            "dx": str(WIDTH), "dy": str(HEIGHT), "grid": "1", "gridSize": "10",
            "guides": "1", "tooltips": "1", "connect": "1", "arrows": "1",
            "page": "1", "pageScale": "1", "pageWidth": str(WIDTH),
            "pageHeight": str(HEIGHT), "background": "#ffffff"})
        self.root = ET.SubElement(self.graph, "root")
        ET.SubElement(self.root, "mxCell", {"id": "0"})
        ET.SubElement(self.root, "mxCell", {"id": "1", "parent": "0"})
        self.boxes, self.routes, self.texts = {}, [], []
        self.text("title", title, 60, 30, 1480, 45, 28, True)
        self.text("subtitle", subtitle, 60, 80, 1480, 50, 15)

    def text(self, key, label, x, y, w, h, size=14, bold=False):
        label = wrap_label(label, w, size)
        cell = ET.SubElement(self.root, "mxCell", {
            "id": f"{self.id}:{key}", "value": html.escape(label).replace("\n", "<br>"),
            "vertex": "1", "parent": "1", "style":
            f"text;html=1;whiteSpace=wrap;align=left;verticalAlign=middle;"
            f"fontFamily={FONT};fontColor=#263343;fontSize={size};fontStyle={int(bold)};"})
        ET.SubElement(cell, "mxGeometry", {"x": str(x), "y": str(y), "width": str(w),
                                           "height": str(h), "as": "geometry"})
        self.texts.append((label, x, y, w, h, size, bold))

    def node(self, key, label, x, y, w=260, h=120, slot="primary", kind="service",
             source=None, members=None, dashed=False):
        if key not in NODES:
            model_node(key, label.split("\n")[0], kind, source, members=members or [],
                       abstraction="logical summary; not an additional container")
        m = NODES[key]
        color = PALETTE[slot]
        style = ("shape=cylinder3;boundedLbl=1;size=15;" if kind == "database" else "rounded=1;arcSize=12;")
        style += (f"whiteSpace=wrap;html=1;fillColor={color['fillColor']};"
                  f"strokeColor={color['strokeColor']};strokeWidth=2;fontColor=#263343;"
                  f"fontFamily={FONT};fontSize=16;spacing=12;")
        if dashed:
            style += "dashed=1;dashPattern=7 5;"
        lines = label.splitlines()
        label = "\n".join([wrap_label(lines[0], w-28, 17),
                            *[wrap_label(line, w-28, 14) for line in lines[1:]]])
        lines = label.splitlines()
        value = f'<span style="font-size:17px"><b>{html.escape(lines[0])}</b></span><br>'
        value += '<span style="font-size:14px">' + '<br>'.join(html.escape(line) for line in lines[1:]) + '</span>'
        cell = ET.SubElement(self.root, "mxCell", {
            "id": f"{self.id}:{key}", "value": value,
            "style": style, "vertex": "1", "parent": "1", "data-model-id": key,
            "data-kind": kind, "data-properties": json.dumps(m["properties"], ensure_ascii=False),
            "data-provenance": json.dumps(m["provenance"], ensure_ascii=False)})
        ET.SubElement(cell, "mxGeometry", {"x": str(x), "y": str(y), "width": str(w),
                                           "height": str(h), "as": "geometry"})
        self.boxes[key] = {"label": label, "x": x, "y": y, "w": w, "h": h,
                           "slot": slot, "kind": kind, "dashed": dashed}

    def edge(self, source, target, label="", start="R", end="L", via=(),
             label_at=None, slot="neutral", dashed=False, provenance=None):
        anchors = {"L": (0, .5), "R": (1, .5), "T": (.5, 0), "B": (.5, 1)}
        sx, sy = anchors[start] if isinstance(start, str) else start
        tx, ty = anchors[end] if isinstance(end, str) else end
        a, b = self.boxes[source], self.boxes[target]
        pts = [(a["x"] + sx*a["w"], a["y"] + sy*a["h"]), *via,
               (b["x"] + tx*b["w"], b["y"] + ty*b["h"])]
        edge_id = f"flow:{self.id}:{len(self.routes)}"
        color = PALETTE[slot]["strokeColor"]
        style = (f"edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;"
                 f"html=1;endArrow=classic;endFill=1;strokeWidth=2;strokeColor={color};"
                 f"fontFamily={FONT};fontSize=14;labelBackgroundColor=#ffffff;"
                 f"exitX={sx};exitY={sy};exitPerimeter=0;entryX={tx};entryY={ty};entryPerimeter=0;")
        if dashed:
            style += "dashed=1;dashPattern=7 5;"
        cell = ET.SubElement(self.root, "mxCell", {
            "id": edge_id, "value": "", "style": style, "edge": "1", "parent": "1",
            "source": f"{self.id}:{source}", "target": f"{self.id}:{target}",
            "data-model-id": edge_id, "data-kind": "dataflow",
            "data-source-label": label,
            "data-provenance": json.dumps(provenance or {}, ensure_ascii=False)})
        geom = ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})
        if via:
            arr = ET.SubElement(geom, "Array", {"as": "points"})
            for px, py in via:
                ET.SubElement(arr, "mxPoint", {"x": str(px), "y": str(py)})
        if label:
            lx, ly, lw = label_at
            # Explicit label cells keep the renderer and editable document aligned.
            self.text(f"label{len(self.routes)}", label, lx, ly, lw, 40, 13)
        self.routes.append({"points": pts, "color": color, "dashed": dashed})
        EDGES.append({"id": edge_id, "source": source, "target": target,
                      "label": label, "kind": "dataflow", "provenance": provenance or {}})

    def finish(self, notes):
        self.text("notes", notes, 60, 1000, 1480, 90, 14)
        VIEWS.append({"id": self.id, "name": self.name, "nodes": list(self.boxes)})


P = evidence("monitoring/prometheus/prometheus.yml", "scrape_configs:")
F = evidence("leafy/fluentd/fluent.conf", "<source>")
N = evidence("aiops/pipeline/collector/network.py", "class NetworkCollector")
R = evidence("aiops/remediation/main.py", 'if action_risk == "low"')
A = evidence("monitoring/alertmanager/alertmanager.yml", "webhook_configs:")
M = evidence("aiops/pipeline/main.py", "async def analyze_alerts")

p1 = Page("overview", "01 전체 구조", "Leafy AIOps | 전체 아키텍처",
          "Compose 선언 + 현재 코드 기준의 핵심 경로이다. 실행 상태는 조회하지 않았으며, Remediation 중지는 사용자 제공 상태이다.")
p1.node("leafy-apps", "Leafy 애플리케이션\nfrontend · backend · db · minio\nleafy-net (+ backend: mgmt-net)", 60, 180, 300, 140,
        members=["frontend", "backend", "db", "minio"], source=evidence("docker-compose.yml", "services:"))
p1.node("exporters", "메트릭 수집기\nnode-exporter · cadvisor\nnginx-exporter\npostgres-exporter", 450, 180, 270, 140,
        slot="accent", members=["node-exporter", "cadvisor", "nginx-exporter", "postgres-exporter"], source=P)
p1.node("prometheus", "Prometheus :9090\n5초 scrape / 규칙 평가\n메트릭 30일 보존", 830, 180, 270, 140, slot="success", kind="database")
p1.node("alertmanager", "Alertmanager :9093\nPrometheus + Loki Alert 수신\nPipeline webhook 전달", 1220, 180, 300, 140, slot="warning")
p1.node("network-observer", "Network Observer\nZeek → Enricher\nbackend 네임스페이스의 eth0 관측", 60, 480, 300, 140,
        slot="secondary", members=["network-observer-zeek", "network-observer-enricher"],
        source=evidence("docker-compose.yml", 'network_mode: "service:backend"'))
p1.node("fluentd", "Fluentd :24224 TCP/UDP\n앱 forward + 네트워크 파일 tail\n별도 경로로 Loki에 적재", 450, 480, 270, 140, slot="accent")
p1.node("loki", "Loki :3100\n앱·네트워크·분석 로그 저장\n로그 패턴 규칙 / Ruler", 830, 480, 270, 140, slot="success", kind="database")
p1.node("pipeline", "AIOps Pipeline :8000\nAlert → 컨텍스트 상관 → RCA\nPrometheus·Loki 조회 / 결과 기록", 1220, 480, 300, 140)
p1.node("grafana", "Grafana :3000\nPrometheus + Loki 조회\n메트릭·로그·RCA 타임라인", 450, 790, 270, 140, slot="neutral")
p1.node("ollama", "Ollama :11434\nllama3.2:3b / 로컬 추론\nGPU override 선택", 830, 790, 270, 140, slot="secondary")
p1.node("remediation", "Remediation :8001\n현재 중지 유지\n기동 시에만 Docker 조치·Slack 연계", 1220, 790, 300, 140, slot="danger", dashed=True)
p1.edge("leafy-apps", "network-observer", "backend eth0 캡처", "B", "T", label_at=(80, 380, 270), slot="secondary")
p1.edge("leafy-apps", "fluentd", "Docker 데몬 localhost:24224", end="T", via=[(400, 250), (400, 400), (585, 400)],
        label_at=(440, 350, 330), slot="accent", provenance=F)
p1.edge("exporters", "prometheus", "메트릭 응답", label_at=(730, 200, 100), provenance=P)
p1.edge("prometheus", "alertmanager", "Alert 전송", label_at=(1110, 200, 100), slot="warning", provenance=P)
p1.edge("network-observer", "fluentd", "이벤트\nJSONL", label_at=(365, 500, 80), slot="secondary", provenance=F)
p1.edge("fluentd", "loki", "로그 적재", label_at=(735, 500, 95), slot="accent", provenance=F)
p1.edge("loki", "pipeline", "컨텍스트\n조회", label_at=(1110, 500, 100), provenance=N)
p1.edge("alertmanager", "pipeline", "/webhook/alert", "B", "T", label_at=(1400, 355, 120), slot="warning", provenance=A)
p1.edge("loki", "alertmanager", "Ruler Alert", "T", (0, .75), [(965, 400), (1160, 400), (1160, 285)], (990, 345, 150), "warning",
        provenance=evidence("monitoring/loki/loki-config.yml", "alertmanager_url:"))
p1.edge("pipeline", "ollama", "POST /api/chat", (.25, 1), "R", [(1295, 690), (1160, 690), (1160, 860)], (1040, 635, 200), "secondary",
        provenance=evidence("aiops/pipeline/main.py", 'f"{settings.ollama_url}/api/chat"'))
p1.edge("pipeline", "remediation", "/action 시도\n중지 중 실패", (.75, 1), "T", [(1445, 730), (1370, 730)],
        label_at=(1310, 635, 120), slot="danger", dashed=True, provenance=R)
p1.edge("grafana", "loki", "조회", "T", "B", [(585, 710), (965, 710)], (700, 660, 80),
        provenance=evidence("monitoring/grafana/provisioning/datasources/datasources.yml", "url: http://loki"))
p1.finish("파란색: 앱·분석 / 주황색: 수집 / 초록색: 저장 / 보라색: 네트워크·LLM / 빨간 점선: 중지된 대응 경로이다.\n전체 컨테이너 연결과 양방향 요청·응답은 가독성을 위해 요약하며, 상세 흐름은 다음 페이지에 표시한다.")

p2 = Page("logs-network", "02 로그와 네트워크", "관측 데이터 | Application Logs + Network Events",
          "서비스 이름은 Compose identity이다. 실선은 데이터 전달, 보라색 선은 네트워크 관측과 정규화 경로이다.")
for key, label, x, slot, kind in [
    ("frontend", "frontend / nginx\n10.210.0.10 · 웹 :80\nleafy-net", 60, "primary", "service"),
    ("backend", "backend / Spring Boot\nleafy-net + mgmt-net\n외부 Leafy 이미지", 450, "primary", "service"),
    ("db", "db / PostgreSQL 16\n내부 :5432\nleafy-net", 830, "success", "database"),
    ("minio", "minio / Object Storage\n내부 :9000\nleafy-net", 1220, "success", "database"),
]:
    p2.node(key, label, x, 180, 270 if x != 1220 else 300, 140, slot, kind)
p2.node("docker-log-driver", "앱 stdout / stderr\n4개 컨테이너의 fluentd 드라이버\nDocker 데몬 기준 localhost:24224", 60, 480, 300, 140, slot="neutral", members=["frontend", "backend", "db", "minio"], source=F)
p2.node("fluentd", "Fluentd\n앱: forward → key_value\n네트워크: @NETWORK → JSON", 450, 480, 270, 140, slot="accent")
p2.node("loki", "Loki\n앱: service / container_name\n네트워크: src_service / dst_service", 830, 480, 270, 140, slot="success", kind="database")
p2.node("pipeline", "Pipeline 컨텍스트 조회\n앱: {service=…}\n네트워크: src/dst 2개 selector", 1220, 480, 300, 140)
p2.node("network-observer-zeek", "Zeek\nnetwork_mode: service:backend\nzeek -C -i eth0", 60, 790, 300, 140, slot="secondary")
p2.node("vol:zeek_logs", "zeek_logs 볼륨\nconn.log / JSON Lines\nEnricher가 읽기 전용 tail", 450, 790, 270, 140, slot="neutral", kind="database")
p2.node("network-observer-enricher", "Enricher\nDocker metadata → endpoint identity\nCanonical Network Event v1.0", 830, 790, 270, 140, slot="secondary")
p2.node("vol:network_events", "network_events 볼륨\nnetwork-events.jsonl\nFluentd가 읽기 전용 tail", 1220, 790, 300, 140, slot="neutral", kind="database")
p2.edge("frontend", "backend", "HTTP", label_at=(350, 200, 95))
p2.edge("backend", "db", "JDBC", label_at=(730, 200, 95))
p2.edge("backend", "minio", "Object API", "B", "B", [(585, 370), (1370, 370)], (940, 330, 140))
p2.edge("docker-log-driver", "fluentd", "forward\n:24224", label_at=(365, 500, 80), slot="accent", provenance=F)
p2.edge("fluentd", "loki", "5초 flush", label_at=(735, 500, 90), slot="accent", provenance=F)
p2.edge("loki", "pipeline", "동일 service\n같은 시간창", label_at=(1110, 500, 100), provenance=N)
p2.edge("backend", "network-observer-zeek", "네임스페이스 공유 / eth0만 관측", "L", "L",
        [(400, 250), (400, 420), (30, 420), (30, 860)], (60, 370, 330), "secondary")
p2.edge("network-observer-zeek", "vol:zeek_logs", "연결 로그", label_at=(360, 810, 90), slot="secondary")
p2.edge("vol:zeek_logs", "network-observer-enricher", "tail", label_at=(745, 810, 75), slot="secondary")
p2.edge("network-observer-enricher", "vol:network_events", "정규화 JSONL", label_at=(1100, 810, 120), slot="secondary")
p2.edge("vol:network_events", "fluentd", "별도 @NETWORK 경로 / 원본 JSON 보존", "T", "B",
        [(1370, 710), (585, 710)], (760, 655, 460), "secondary", provenance=F)
p2.finish("leafy-net: 10.210.0.0/24 / Zeek는 독립 네트워크 없이 backend 네임스페이스를 공유한다.\n네트워크 이벤트는 보조 컨텍스트이다. 연결 종료 지연·관측 누락이 가능하며, 빈 결과를 정상으로 단정하지 않는다.")

p3 = Page("rca-response", "03 분석과 대응", "Alert → Context → LLM RCA → Remediation",
          "Pipeline 내부 처리 단계와 외부 서비스를 구분한 흐름이다. 현재 Remediation 중지로 아래 점선 경로는 실행되지 않는다.")
p3.node("prometheus", "Prometheus 규칙\n메트릭 임계값 Alert 6종\nexporter 4종 + backend + Pipeline 수집", 60, 180, 300, 140, slot="success")
p3.node("loki", "Loki Ruler\n보안·로그 패턴 Alert 9종\n애플리케이션 로그 기준", 60, 480, 300, 140, slot="success")
p3.node("alertmanager", "Alertmanager\n모든 Alert → 단일 webhook\ngroup 10초 / repeat 240초", 450, 180, 270, 140, slot="warning")
p3.node("pipeline", "Pipeline /webhook/alert\nfiring만 처리 · 300초 중복 제거\n대상 컨테이너와 service 해석", 830, 180, 270, 140)
p3.node("correlation", "Pipeline: 컨텍스트 수집\nstartsAt ±5분 조회\n메트릭 + 앱 로그 + 네트워크", 1220, 180, 300, 140, source=M)
p3.node("ollama", "Ollama /api/chat\nllama3.2:3b · JSON 응답\n동시 1 · 요청 타임아웃 180초", 1220, 480, 300, 140, slot="secondary")
p3.node("analysis-store", "Pipeline: 분석 결과 기록\nLoki aiops-llm / aiops-timeline\n근본 원인 · 증거 · 권장 조치", 830, 480, 270, 140, slot="success", source=M)
p3.node("fallback-gate", "Pipeline: fallback 검사\nconfidence=0 + action_type=NONE\n해당 시 Remediation 전달 생략", 450, 480, 270, 140, slot="warning", source=M)
p3.node("remediation", "Remediation /action\n현재 중지 유지\n기동 시 위험도·신뢰도로 분기", 60, 790, 300, 140, slot="danger", dashed=True)
p3.node("docker-actions", "Docker API 조치\nRESTART · ISOLATE\nPAUSE · THROTTLE", 450, 790, 270, 140, slot="danger", dashed=True, source=R)
p3.node("slack", "Slack 연계\n승인 요청 또는 알림\nWebhook + 별도 interactivity 필요", 830, 790, 270, 140, slot="neutral", dashed=True,
        source=evidence("aiops/remediation/actions/notify.py", "class Notifier"))
p3.node("grafana", "Grafana 결과 확인\nPrometheus 메트릭 + Loki 로그\nRCA·조치 타임라인 조회", 1220, 790, 300, 140, slot="neutral")
p3.edge("prometheus", "alertmanager", "Alert", label_at=(370, 200, 75), slot="warning", provenance=P)
p3.edge("loki", "alertmanager", "Ruler Alert", "R", "B", [(400, 550), (400, 390), (585, 390)], (430, 410, 200), "warning")
p3.edge("alertmanager", "pipeline", "webhook", label_at=(730, 200, 95), slot="warning", provenance=A)
p3.edge("pipeline", "correlation", "유효 대상", label_at=(1110, 200, 100), provenance=M)
p3.edge("correlation", "ollama", "프롬프트 + JSON 스키마", "B", "T", label_at=(1240, 380, 290), slot="secondary")
p3.edge("ollama", "analysis-store", "분석 응답", "L", "R", label_at=(1100, 500, 110), slot="secondary")
p3.edge("analysis-store", "fallback-gate", "분석 기록 후", "L", "R", label_at=(730, 500, 100))
p3.edge("fallback-gate", "remediation", "fallback이 아닌 경우 전달 시도", "B", "T",
        [(585, 700), (210, 700)], (250, 720, 380), "danger", True, provenance=R)
p3.edge("remediation", "docker-actions", "조건 충족", label_at=(365, 810, 80), slot="danger", dashed=True, provenance=R)
p3.edge("remediation", "slack", "승인 필요 / 알림만", "B", "B", [(210, 970), (965, 970)], (600, 930, 250), "neutral", True)
p3.edge("analysis-store", "grafana", "Loki 데이터 소스 조회", "B", "T", [(965, 700), (1370, 700)], (1090, 650, 280))
p3.finish("자동 조치 조건은 low risk + confidence ≥0.7 + 대상 목록이다. 대상 컨테이너를 결정할 수 없으면 LLM 호출을 생략한다.\nSlack 승인 실행은 RESTART/ISOLATE만 지원하며 SCALE은 미구현이다. ±5분은 조회 범위이며 미래 데이터를 기다리지 않는다.")

PAGES = [p1, p2, p3]
mxfile = ET.Element("mxfile", {"host": "drawio-skill", "version": "26.0.0", "agent": "source-backed architecture"})
for page in PAGES:
    mxfile.append(page.diagram)
ET.indent(mxfile, space="  ")
OUT.mkdir(parents=True, exist_ok=True)
ET.ElementTree(mxfile).write(OUT / "leafy-aiops.drawio", encoding="utf-8", xml_declaration=True)
for node in list(NODES.values()):
    for member in node["properties"].get("members", []):
        EDGES.append({"id": f"membership:{node['id']}:{member}", "source": node["id"],
                      "target": member, "label": "logical summary membership", "kind": "contains"})
model = {"schema": "drawio-skill/diagram-ir/v1", "metadata": {
    "title": "Leafy AIOps — current declared architecture",
    "sources": ["docker-compose.yml", "docker-compose.gpu.yml", "leafy/fluentd/fluent.conf",
                "monitoring/prometheus/prometheus.yml", "monitoring/alertmanager/alertmanager.yml",
                "aiops/pipeline/main.py", "aiops/remediation/main.py"],
    "runtime_inspected": False, "remediation_status_source": "user-provided stopped state",
    "notes": "Summary nodes and processing steps are abstractions, not additional deployed services."},
    "nodes": list(NODES.values()), "edges": EDGES, "views": VIEWS}
(OUT / "leafy-aiops.ir.json").write_text(json.dumps(model, ensure_ascii=False, indent=2) + "\n", "utf-8")

# CLI-independent preview: render exactly the same rectangles, waypoints and labels.
# This is a preview, not draw.io's native SVG/PNG export.
def svg_preview(page):
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{html.escape(page.name)}" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}">',
             f'<title>{html.escape(page.name)}</title><desc>Compose와 코드에서 확인한 구조이다. 실행 상태를 조회한 결과가 아니며 Remediation은 사용자 제공 중지 상태이다.</desc>',
             '<rect width="100%" height="100%" fill="white"/>',
             '<defs><marker id="arrow" markerWidth="9" markerHeight="9" refX="8" refY="4" orient="auto" markerUnits="userSpaceOnUse"><path d="M0,0 L8,4 L0,8 Z" fill="context-stroke"/></marker></defs>']
    for route in page.routes:
        d = "M " + " L ".join(f"{x},{y}" for x, y in route["points"])
        dash = ' stroke-dasharray="7 5"' if route["dashed"] else ""
        parts.append(f'<path d="{d}" fill="none" stroke="{route["color"]}" stroke-width="2" marker-end="url(#arrow)"{dash}/>')
    for key, box in page.boxes.items():
        x, y, w, h = (box[k] for k in ("x", "y", "w", "h"))
        colors = PALETTE[box["slot"]]
        dash = ' stroke-dasharray="7 5"' if box["dashed"] else ""
        source = NODES[key]["provenance"]
        tooltip = f'{key} — {source.get("path", "logical summary")}:{source.get("line", "")}'
        parts.append(f'<g data-cell-id="{html.escape(key)}"><title>{html.escape(tooltip)}</title><rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{colors["fillColor"]}" stroke="{colors["strokeColor"]}" stroke-width="2"{dash}/>')
        if box["kind"] == "database":
            parts.append(f'<path d="M{x},{y+18} Q{x+w/2},{y+44} {x+w},{y+18}" fill="none" stroke="{colors["strokeColor"]}"/>')
        lines = box["label"].splitlines()
        for i, line in enumerate(lines):
            yy = y + h/2 - (len(lines)-1)*13 + i*26
            parts.append(f'<text x="{x+w/2}" y="{yy}" text-anchor="middle" dominant-baseline="middle" font-family="{FONT},sans-serif" font-size="{17 if i == 0 else 14}" font-weight="{600 if i == 0 else 400}" fill="#263343">{html.escape(line)}</text>')
        parts.append("</g>")
    for label, x, y, w, h, size, bold in page.texts:
        for i, line in enumerate(label.splitlines()):
            parts.append(f'<text x="{x}" y="{y+size+4+i*(size+7)}" font-family="{FONT},sans-serif" font-size="{size}" font-weight="{700 if bold else 400}" fill="#263343">{html.escape(line)}</text>')
    parts.append("</svg>")
    return "".join(parts)


spec = importlib.util.spec_from_file_location("drawiohtml", SKILL / "scripts/drawiohtml.py")
viewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(viewer)
svgs = [svg_preview(p) for p in PAGES]
document = viewer.build_html("Leafy AIOps | 현재 아키텍처", [(p.id, p.name) for p in PAGES], svgs)
document = document.replace('<html lang="en">', '<html lang="ko">')
alternative = '<details style="padding:8px 20px;max-height:220px;overflow:auto"><summary>다이어그램의 텍스트 설명과 코드 근거</summary>'
for page in PAGES:
    alternative += f'<section><h2>{html.escape(page.name)}</h2><ul>'
    for key, box in page.boxes.items():
        source = NODES[key]["provenance"]
        label = box["label"].replace("\n", " · ")
        alternative += f'<li>{html.escape(label)} — {html.escape(source.get("path", ""))}:{source.get("line", "")}</li>'
    alternative += '</ul></section>'
alternative += '</details>'
document = document.replace('</main>', '</main>' + alternative)
(OUT / "leafy-aiops.html").write_text(document, "utf-8")
for page, svg in zip(PAGES, svgs):
    (OUT / f"{page.id}.svg").write_text(svg, "utf-8")
print(f"Created 3 editable pages; source model: {len(NODES)} nodes / {len(EDGES)} relationships.")
print("Preview HTML is self-contained and does not require the draw.io desktop CLI.")
