from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


_TEMPLATE = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>Netra · __NETRA_TITLE__</title>
<style>
:root { color-scheme:dark; --bg:#091015; --panel:#111c23; --ink:#e8f1f5; --muted:#91a5b1; --accent:#46d2b0 }
* { box-sizing:border-box }
body { margin:0; font:14px/1.45 system-ui,sans-serif; background:var(--bg); color:var(--ink) }
header { padding:20px 24px; border-bottom:1px solid #22333d; display:flex; justify-content:space-between; gap:20px }
h1 { margin:0; font-size:20px }
.muted { color:var(--muted) }
main { display:grid; grid-template-columns:minmax(0,1fr) 360px; min-height:calc(100vh - 75px) }
#graph { width:100%; height:calc(100vh - 75px); background:radial-gradient(circle at center,#14242d 0,#091015 65%) }
aside { border-left:1px solid #22333d; padding:18px; overflow:auto; max-height:calc(100vh - 75px) }
.card { background:var(--panel); border:1px solid #263943; border-radius:10px; padding:13px; margin:0 0 12px }
button { width:100%; text-align:left; background:none; color:inherit; border:0; cursor:pointer; padding:7px 0 }
button:hover { color:var(--accent) }
code { color:#a8ead9 }
pre { white-space:pre-wrap; color:#bdd0d8 }
@media(max-width:850px) {
  main { grid-template-columns:1fr }
  aside { border-left:0; border-top:1px solid #22333d; max-height:none }
  #graph { height:60vh }
}
</style>
</head>
<body>
<header>
  <div><h1>NETRA · mapa basado en evidencias</h1><div class="muted" id="run"></div></div>
  <div class="muted">continua: observada · discontinua: inferida · tenue: lógica/desconocida</div>
</header>
<main>
  <svg id="graph" role="img" aria-label="Topología de red"></svg>
  <aside>
    <div id="summary" class="card"></div>
    <div id="issues" class="card"></div>
    <div id="detail" class="card">Selecciona un nodo o una relación.</div>
    <div class="card"><strong>Relaciones</strong><div id="relations"></div></div>
  </aside>
</main>
<script id="netra-data" type="application/json">__NETRA_DATA__</script>
<script>
const data = JSON.parse(document.getElementById('netra-data').textContent);
const svg = document.getElementById('graph');
const NS = 'http://www.w3.org/2000/svg';
const assets = data.assets || [];
const rels = data.relationships || [];
const issues = data.coverage?.issues || [];

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
  })[character]);
}

document.getElementById('run').textContent =
  `Ejecución ${data.run?.id || '—'} · ${(data.run?.scope || []).join(', ') || 'sin alcance'}`;
document.getElementById('summary').innerHTML =
  `<strong>Cobertura</strong><p>${assets.length} activos · ${rels.length} relaciones · ${issues.length} incidencias</p>` +
  `<span class="muted">${esc(data.coverage?.statement || 'Sin declaración de cobertura')}</span>`;
document.getElementById('issues').innerHTML = '<strong>Incidencias de cobertura</strong>' + (
  issues.length
    ? issues.map(issue =>
        `<p><code>${esc(issue.source)}/${esc(issue.stage)}</code><br>` +
        `<span class="muted">${esc(issue.target || '')} ${esc(issue.error)}</span></p>`
      ).join('')
    : '<p class="muted">Ninguna registrada.</p>'
);

function element(name, attributes = {}) {
  const node = document.createElementNS(NS, name);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
  return node;
}

const width = 1000, height = 700, centerX = width / 2, centerY = height / 2;
const radius = Math.min(width, height) * .36;
svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
const positions = new Map();
assets.forEach((asset, index) => {
  const angle = Math.PI * 2 * index / Math.max(assets.length, 1) - Math.PI / 2;
  positions.set(asset.id, {x:centerX + Math.cos(angle) * radius, y:centerY + Math.sin(angle) * radius});
});

rels.forEach(relation => {
  const from = positions.get(relation.from), to = positions.get(relation.to);
  if (!from || !to) return;
  const line = element('line', {
    x1:from.x, y1:from.y, x2:to.x, y2:to.y,
    stroke:relation.state === 'observed' ? '#46d2b0' : '#5d7582',
    'stroke-width':relation.state === 'observed' ? 3 : 2,
    'stroke-dasharray':relation.state === 'inferred' ? '9 7' : relation.state === 'unknown' ? '3 8' : 'none',
    opacity:relation.type === 'reachable_via' ? .55 : 1
  });
  line.style.cursor = 'pointer';
  line.onclick = () => show(relation, 'Relación');
  svg.appendChild(line);
});

assets.forEach(asset => {
  const position = positions.get(asset.id), group = element('g');
  group.style.cursor = 'pointer';
  const circle = element('circle', {cx:position.x, cy:position.y, r:34, fill:'#142b33', stroke:'#46d2b0', 'stroke-width':2});
  const label = element('text', {x:position.x, y:position.y + 54, fill:'#e8f1f5', 'text-anchor':'middle', 'font-size':13});
  label.textContent = (asset.names?.[0] || asset.addresses?.[0] || asset.macs?.[0] || asset.id).slice(0, 24);
  group.append(circle, label);
  group.onclick = () => show(asset, 'Activo');
  svg.appendChild(group);
});

function show(object, label) {
  document.getElementById('detail').innerHTML =
    `<strong>${label}</strong><pre>${esc(JSON.stringify(object, null, 2))}</pre>`;
}

document.getElementById('relations').innerHTML = rels.map((relation, index) =>
  `<button data-i="${index}"><code>${esc(relation.type)}</code><br>` +
  `<span class="muted">${esc(relation.from)} → ${esc(relation.to)} · ${esc(relation.state)}</span></button>`
).join('') || '<p class="muted">No hay relaciones.</p>';
document.querySelectorAll('#relations button').forEach(button => {
  button.onclick = () => show(rels[Number(button.dataset.i)], 'Relación');
});
</script>
</body>
</html>
"""


def build_html(artifact: dict[str, Any], destination: Path) -> None:
    safe_data = json.dumps(artifact, ensure_ascii=False).replace("</", "<\\/")
    title = html.escape(str(artifact.get("run", {}).get("id", "Netra")))
    document = _TEMPLATE.replace("__NETRA_DATA__", safe_data, 1).replace(
        "__NETRA_TITLE__", title, 1
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")
