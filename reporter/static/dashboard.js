'use strict';

// Values shown here can come from attackers (usernames, log text), so everything is
// written through textContent. Do not switch any of this to innerHTML.

const REFRESH_MS = 5000;
const SVG_NS = 'http://www.w3.org/2000/svg';
const SERIES = [
  { key: 'event_counts', label: 'Events', css: 's1' },
  { key: 'alert_counts', label: 'Alerts', css: 's2' },
  { key: 'response_counts', label: 'Responses', css: 's3' },
];

let currentWindow = '24h';
let lastSummary = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function svg(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs || {}).forEach(([name, value]) => node.setAttribute(name, value));
  return node;
}

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function replace(id, children) {
  document.getElementById(id).replaceChildren(...children);
}

async function getJson(url) {
  const response = await fetch(url, { cache: 'no-store' });
  if (response.status === 401) {
    window.location.assign('/login');
    throw new Error('Signed out');
  }
  if (!response.ok) throw new Error(`${url} returned ${response.status}`);
  return response.json();
}

function shortTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso || '';
  return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function duration(seconds) {
  const minutes = Math.round(seconds / 60);
  if (minutes < 1) return 'under a minute';
  if (minutes < 60) return `${minutes} min`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

// The chart shows counts, so the four axis steps must be whole numbers.
function niceStep(peak) {
  const target = Math.max(1, peak / 4);
  const magnitude = 10 ** Math.floor(Math.log10(target));
  const multiple = [1, 2, 3, 4, 5, 6, 8, 10].find((m) => m * magnitude >= target);
  return Math.max(1, Math.round(multiple * magnitude));
}

function renderLegend() {
  replace('legend', SERIES.map((series) => {
    const item = el('span');
    item.append(el('span', `swatch ${series.css}`), document.createTextNode(series.label));
    return item;
  }));
}

function renderChart(data) {
  const box = document.getElementById('chart');
  const width = box.clientWidth || 800;
  const height = box.clientHeight || 280;
  const pad = { top: 10, right: 12, bottom: 24, left: 40 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const count = data.labels.length;

  const peak = Math.max(1, ...SERIES.flatMap((series) => data[series.key]));
  const step = niceStep(peak);
  const top = step * 4;
  const x = (i) => pad.left + (count > 1 ? (plotW * i) / (count - 1) : 0);
  const y = (value) => pad.top + plotH - (plotH * value) / top;

  const root = svg('svg', {
    viewBox: `0 0 ${width} ${height}`,
    role: 'img',
    'aria-label': 'Events, alerts and responses over the selected time range',
  });

  for (let tick = 0; tick <= 4; tick += 1) {
    const value = step * tick;
    root.append(svg('line', {
      class: 'grid-line', x1: pad.left, x2: width - pad.right, y1: y(value), y2: y(value),
    }));
    const label = svg('text', { class: 'axis end', x: pad.left - 6, y: y(value) + 4 });
    label.textContent = value;
    root.append(label);
  }

  const every = Math.max(1, Math.ceil(count / Math.max(2, Math.floor(plotW / 110))));
  data.labels.forEach((iso, i) => {
    if (i % every !== 0) return;
    const label = svg('text', { class: 'axis mid', x: x(i), y: height - 6 });
    label.textContent = shortTime(iso);
    root.append(label);
  });

  SERIES.forEach((series) => {
    const points = data[series.key].map((value, i) => `${x(i)},${y(value)}`).join(' ');
    root.append(svg('polyline', { class: `line ${series.css}`, points }));
  });

  const crosshair = svg('line', {
    class: 'crosshair', y1: pad.top, y2: pad.top + plotH, visibility: 'hidden',
  });
  root.append(crosshair);

  const tooltip = el('div', 'tooltip');
  tooltip.hidden = true;

  const showAt = (clientX) => {
    const bounds = box.getBoundingClientRect();
    const position = clientX - bounds.left;
    const ratio = (position - pad.left) / plotW;
    const index = Math.max(0, Math.min(count - 1, Math.round(ratio * (count - 1))));
    crosshair.setAttribute('x1', x(index));
    crosshair.setAttribute('x2', x(index));
    crosshair.setAttribute('visibility', 'visible');

    const rows = SERIES.map((series) => {
      const row = el('div');
      row.append(el('span', '', series.label), el('b', '', String(data[series.key][index])));
      return row;
    });
    tooltip.replaceChildren(el('span', 'muted', shortTime(data.labels[index])), ...rows);
    tooltip.hidden = false;

    const left = x(index) + 12;
    const fits = left + tooltip.offsetWidth < width;
    tooltip.style.left = `${fits ? left : x(index) - tooltip.offsetWidth - 12}px`;
  };

  root.addEventListener('pointermove', (event) => showAt(event.clientX));
  root.addEventListener('pointerleave', () => {
    crosshair.setAttribute('visibility', 'hidden');
    tooltip.hidden = true;
  });

  box.replaceChildren(root, tooltip);
}

function renderBars(id, rows, emptyText) {
  if (!rows.length) {
    replace(id, [el('p', 'empty', emptyText)]);
    return;
  }
  const peak = Math.max(...rows.map((row) => row.count));
  replace(id, rows.map((row) => {
    const line = el('div', 'bar-row');
    const label = el('span', 'bar-label', row.label);
    label.title = row.title || row.label;
    const track = el('div', 'bar-track');
    const bar = el('div', 'bar');
    bar.style.width = `${(row.count / peak) * 100}%`;
    track.append(bar);
    line.append(label, track, el('span', 'bar-value', String(row.count)));
    return line;
  }));
}

function emptyRow(columns, text) {
  const row = el('tr');
  const cell = el('td', 'empty', text);
  cell.colSpan = columns;
  row.append(cell);
  return row;
}

function row(cells) {
  const line = el('tr');
  cells.forEach((cell) => line.append(cell instanceof Node ? cell : el('td', '', String(cell))));
  return line;
}

function severityCell(severity) {
  const cell = el('td', 'nowrap');
  cell.append(el('span', `dot ${severity}`), document.createTextNode(severity));
  return cell;
}

function chip(text) {
  return el('span', 'chip', text);
}

function incidentFacts(item) {
  const facts = el('dl', 'facts');
  const add = (label, value) => {
    if (!value) return;
    facts.append(el('dt', '', label), el('dd', '', value));
  };
  add('Source', item.ips.join(', '));
  add('Accounts', item.users.join(', '));
  add('Techniques', item.techniques.join(', '));
  return facts;
}

function incidentTimeline(item) {
  const list = el('ol', 'timeline');
  item.timeline.forEach((step) => {
    const line = el('li');
    line.append(
      el('span', 'nowrap muted', shortTime(step.ts)),
      severityCell2(step.severity),
      el('span', '', step.reason),
    );
    if (step.action !== 'none') line.append(chip(`${step.action} ${step.target}`));
    list.append(line);
  });
  return list;
}

// A label always sits beside the dot, so severity never depends on colour alone.
function severityCell2(severity) {
  const label = el('span', 'nowrap');
  label.append(el('span', `dot ${severity}`), document.createTextNode(severity));
  return label;
}

function incidentResponses(item) {
  if (!item.responses.length) return null;
  const list = el('ul', 'plain');
  item.responses.forEach((step) => {
    const status = step.status === 'dry_run' ? 'dry run' : step.status;
    list.append(el('li', '', `${step.action} ${step.target}: ${status}. ${step.detail}`));
  });
  return list;
}

function renderIncidents(items) {
  if (!items.length) {
    replace('incidents', [el('p', 'empty', 'No incidents recorded yet.')]);
    return;
  }
  const open = new Set(
    [...document.querySelectorAll('#incidents details[open]')].map((node) => node.dataset.id),
  );
  replace('incidents', items.slice(0, 12).map((item) => {
    const details = el('details', 'incident');
    details.dataset.id = item.id;
    details.open = open.has(item.id);

    const summary = el('summary');
    summary.append(severityCell2(item.severity), el('b', '', String(item.score)), el('span', 'grow', item.summary));
    details.append(summary);

    const body = el('div', 'incident-body');
    if (item.stages.length) {
      const stages = el('div', 'stages');
      item.stages.forEach((stage) => stages.append(chip(stage)));
      body.append(stages);
    }
    body.append(incidentFacts(item), el('h3', '', 'Timeline'), incidentTimeline(item));
    const responses = incidentResponses(item);
    if (responses) body.append(el('h3', '', 'Response'), responses);
    if (item.advice.length) {
      const advice = el('ul', 'plain');
      item.advice.forEach((text) => advice.append(el('li', '', text)));
      body.append(el('h3', '', 'What to do'), advice);
    }
    details.append(body);
    return details;
  }));
}

function renderThreats(items) {
  replace('threats', items.length ? items.slice(0, 25).map((item) => row([
    el('td', 'nowrap', shortTime(item.ts)),
    item.score,
    severityCell(item.severity),
    item.action,
    item.target || '–',
    item.reason,
    item.mitre.join(', ') || '–',
  ])) : [emptyRow(7, 'No threats recorded yet.')]);
}

function renderActions(items) {
  replace('actions', items.length ? items.slice(0, 15).map((item) => row([
    el('td', 'nowrap', shortTime(item.ts)),
    item.action,
    item.target,
    item.status === 'dry_run' ? 'dry run' : item.status,
    item.detail,
  ])) : [emptyRow(5, 'No response actions yet.')]);
}

function renderBlocked(items) {
  setText('t-blocked', items.length);
  replace('blocked', items.length ? items.slice(0, 15).map((item) => row([
    item.ip,
    duration(item.expires_in),
    item.dry_run ? 'dry run' : 'enforced',
  ])) : [emptyRow(3, 'No active blocks.')]);
}

function renderStatus(status) {
  const badge = document.getElementById('mode');
  const enforcing = status.mode === 'enforce';
  badge.textContent = enforcing ? 'Enforcing' : 'Dry run: no real actions';
  badge.classList.toggle('enforce', enforcing);

  const names = Object.keys(status.components || {});
  replace('components', names.length ? names.map((name) => {
    const info = status.components[name];
    const item = el('div');
    const label = info.state === 'unavailable' ? 'not in use' : info.state;
    item.append(el('span', `dot ${info.state}`), document.createTextNode(`${name}: ${label}`));
    if (info.restarts) item.append(document.createTextNode(` (${info.restarts} restarts)`));
    return item;
  }) : [el('p', 'empty', 'The supervisor is not running.')]);
}

function renderSummary(data) {
  lastSummary = data;
  document.getElementById('capped').hidden = !data.threats_capped;
  setText('t-events', data.totals.events);
  setText('t-alerts', data.totals.alerts);
  setText('t-responses', data.totals.responses);
  setText('t-critical', data.severity.critical);
  setText('t-high', data.severity.high);
  renderChart(data);
  renderBars('top-ips', data.top_ips.map((item) => ({ label: item.name, count: item.count })), 'No source IPs in this range.');
  renderBars('mitre', data.mitre.map((item) => ({
    label: `${item.id} ${item.name}`.trim(),
    count: item.count,
  })), 'No techniques in this range.');
}

async function refresh() {
  const banner = document.getElementById('error');
  try {
    const [summary, incidents, threats, actions, blocked, status] = await Promise.all([
      getJson(`/api/summary?window=${encodeURIComponent(currentWindow)}`),
      getJson('/api/incidents'),
      getJson('/api/threats'),
      getJson('/api/actions'),
      getJson('/api/blocked'),
      getJson('/api/status'),
    ]);
    renderSummary(summary);
    renderIncidents(incidents);
    renderThreats(threats);
    renderActions(actions);
    renderBlocked(blocked);
    renderStatus(status);
    setText('updated', `Updated ${new Date().toLocaleTimeString()}`);
    banner.hidden = true;
  } catch (error) {
    banner.textContent = `Could not refresh: ${error.message}. The numbers below may be out of date.`;
    banner.hidden = false;
  }
}

function selectWindow(name) {
  currentWindow = name;
  document.querySelectorAll('[data-window]').forEach((button) => {
    button.setAttribute('aria-pressed', String(button.dataset.window === name));
  });
  refresh();
}

document.addEventListener('DOMContentLoaded', () => {
  renderLegend();
  document.querySelectorAll('[data-window]').forEach((button) => {
    button.addEventListener('click', () => selectWindow(button.dataset.window));
  });
  window.addEventListener('resize', () => {
    if (lastSummary) renderChart(lastSummary);
  });
  selectWindow(currentWindow);
  setInterval(refresh, REFRESH_MS);
});
