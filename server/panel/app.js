// Consola de flota de AegisCore.
//
// Modulo ES nativo, sin dependencias ni paso de construccion. Lo que se lee
// aqui es exactamente lo que ejecuta el navegador del operador.
//
// La consola tiene dos fuentes de datos y hace falta entender por que:
//
//   - REST, para el ESTADO: inventario, alertas, reglas. Se pide al abrir una
//     vista y cuando algo la invalida.
//   - WebSocket, para los SUCESOS: una alerta que entra, un endpoint que late,
//     una regla que se publica. Llegan solos, en el instante en que ocurren.
//
// Un panel que solo sondeara llegaria tarde a lo unico que importa. Uno que
// solo escuchara sucesos no sabria pintar nada al abrirse.

'use strict';

// ── Estado de la aplicacion ─────────────────────────────────────────────
const app = {
  token: sessionStorage.getItem('aegis_token') || null,
  usuario: sessionStorage.getItem('aegis_usuario') || null,
  vista: 'topologia',
  agentes: new Map(),   // cn -> vista del agente
  grafoActual: null,
  ws: null,
  reintento: 0,
  seleccionado: null,
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// ── Cliente de la API ───────────────────────────────────────────────────

/** Llama a la API con la sesion actual; si caduca, vuelve al acceso. */
async function api(ruta, opciones = {}) {
  const cab = Object.assign({}, opciones.headers || {});
  if (app.token) cab['Authorization'] = 'Bearer ' + app.token;
  if (opciones.body) cab['Content-Type'] = 'application/json';

  const r = await fetch(ruta, Object.assign({}, opciones, { headers: cab }));
  if (r.status === 401) {
    // La sesion ya no vale: no tiene sentido seguir pintando datos viejos.
    cerrarSesionLocal();
    throw new Error('sesión caducada');
  }
  if (r.status === 204) return null;
  const cuerpo = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(cuerpo.error || ('HTTP ' + r.status));
  return cuerpo;
}

// ── Acceso ──────────────────────────────────────────────────────────────

$('#form-acceso').addEventListener('submit', async (e) => {
  e.preventDefault();
  const usuario = $('#usuario').value.trim();
  const err = $('#error-acceso');
  err.hidden = true;
  try {
    const r = await api('/api/sesion', { method: 'POST', body: JSON.stringify({ usuario }) });
    app.token = r.token;
    app.usuario = usuario;
    sessionStorage.setItem('aegis_token', r.token);
    sessionStorage.setItem('aegis_usuario', usuario);
    entrar();
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  }
});

$('#salir').addEventListener('click', async () => {
  try { await api('/api/sesion', { method: 'DELETE' }); } catch (_) { /* da igual */ }
  cerrarSesionLocal();
});

function cerrarSesionLocal() {
  app.token = null;
  app.usuario = null;
  sessionStorage.removeItem('aegis_token');
  sessionStorage.removeItem('aegis_usuario');
  if (app.ws) { app.ws.close(); app.ws = null; }
  $('#consola').hidden = true;
  $('#acceso').hidden = false;
}

function entrar() {
  $('#acceso').hidden = true;
  $('#consola').hidden = false;
  $('#quien').textContent = app.usuario || '';
  abrirTiempoReal();
  refrescarTodo();
}

// ── Canal en tiempo real ────────────────────────────────────────────────

function abrirTiempoReal() {
  if (!app.token) return;
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${location.host}/api/ws?token=${encodeURIComponent(app.token)}`;
  const ws = new WebSocket(url);
  app.ws = ws;

  ws.onopen = () => {
    app.reintento = 0;
    marcarEnlace(true);
  };

  ws.onmessage = (ev) => {
    let m;
    try { m = JSON.parse(ev.data); } catch (_) { return; }
    manejarEvento(m);
  };

  ws.onclose = () => {
    marcarEnlace(false);
    if (!app.token) return;
    // Reintento con espera creciente y tope: una caida del servidor no debe
    // convertir cada consola abierta en una fuente de trafico en bucle.
    app.reintento = Math.min(app.reintento + 1, 6);
    const espera = Math.min(1000 * 2 ** app.reintento, 30000);
    setTimeout(abrirTiempoReal, espera);
  };

  ws.onerror = () => ws.close();
}

function marcarEnlace(vivo) {
  const el = $('#enlace');
  el.classList.toggle('conectado', vivo);
  el.classList.toggle('desconectado', !vivo);
  el.querySelector('b').textContent = vivo ? 'en vivo' : 'reconectando';
}

/** Aplica un suceso recibido por el canal. */
function manejarEvento(m) {
  switch (m.tipo) {
    case 'instantanea':
      pintarKpis(m.resumen);
      break;

    case 'desincronizada':
      // Se perdieron sucesos: en vez de seguir con un estado incompleto, se
      // vuelve a pedir todo.
      registrarActividad('canal', `se perdieron ${m.perdidos} sucesos; resincronizando`);
      refrescarTodo();
      break;

    case 'latido': {
      const a = app.agentes.get(m.cn);
      if (a) {
        a.rss_kb = m.rss_kb;
        a.amenazas_activas = m.amenazas;
        a.ultimo_latido = new Date().toISOString();
        a.en_linea = true;
        if (app.vista === 'topologia') pintarFlota();
      } else {
        cargarFlota();
      }
      break;
    }

    case 'agente_enrolado':
      registrarActividad('enrolado', `${m.hostname} se enroló en la flota`);
      cargarFlota();
      break;

    case 'alerta_nueva':
      registrarActividad('alerta',
        `[sev ${m.severidad}] ${m.categoria} en ${corto(m.cn)}` +
        (m.tecnica_mitre ? ` (${m.tecnica_mitre})` : ''));
      subirPin();
      if (app.vista === 'alertas') cargarAlertas();
      cargarResumen();
      break;

    case 'aislamiento_cambiado':
      registrarActividad('aislamiento',
        `${corto(m.cn)} ${m.aislado ? 'AISLADO' : 'liberado'} por ${m.por}`);
      cargarFlota();
      cargarResumen();
      break;

    case 'politica_publicada':
      registrarActividad('politica',
        `política v${m.version} publicada (${m.reglas} regla(s) activas)`);
      cargarResumen();
      if (app.vista === 'reglas') cargarReglas();
      break;

    case 'inteligencia_nueva':
      registrarActividad('canal', `${m.objetos} objeto(s) STIX de ${corto(m.cn)}`);
      if (app.vista === 'inteligencia') cargarStix();
      break;
  }
}

function corto(cn) { return cn.length > 22 ? cn.slice(0, 22) + '…' : cn; }

function registrarActividad(clase, texto) {
  const ul = $('#actividad');
  const li = document.createElement('li');
  li.className = clase;
  const hora = new Date().toLocaleTimeString('es-ES', { hour12: false });
  li.innerHTML = `<span class="hora">${hora}</span> `;
  li.appendChild(document.createTextNode(texto));
  ul.prepend(li);
  // La barra lateral es una ventana a lo que pasa ahora, no un historico: el
  // historico esta en la base de datos y se consulta en las tablas.
  while (ul.children.length > 60) ul.lastChild.remove();
}

let pinAlertas = 0;
function subirPin() {
  if (app.vista === 'alertas') return;
  pinAlertas++;
  const p = $('#pin-alertas');
  p.textContent = pinAlertas;
  p.hidden = false;
}

// ── Navegacion ──────────────────────────────────────────────────────────

$('#pestanas').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-vista]');
  if (!b) return;
  app.vista = b.dataset.vista;
  $$('#pestanas button').forEach((x) => x.classList.toggle('activa', x === b));
  $$('.vista').forEach((v) => { v.hidden = v.id !== 'vista-' + app.vista; });
  if (app.vista === 'alertas') { pinAlertas = 0; $('#pin-alertas').hidden = true; }
  refrescarVista();
});

function refrescarTodo() {
  cargarResumen();
  cargarFlota();
  refrescarVista();
}

function refrescarVista() {
  if (app.vista === 'alertas') cargarAlertas();
  else if (app.vista === 'reglas') cargarReglas();
  else if (app.vista === 'inteligencia') cargarStix();
  else if (app.vista === 'linaje') cargarGrafos();
}

// ── Indicadores ─────────────────────────────────────────────────────────

async function cargarResumen() {
  try { pintarKpis(await api('/api/resumen')); } catch (_) { /* ya avisado */ }
}

function pintarKpis(r) {
  if (!r) return;
  $('#k-total').textContent = r.agentes_total;
  $('#k-linea').textContent = r.agentes_en_linea;
  $('#k-aislados').textContent = r.agentes_aislados;
  $('#k-abiertas').textContent = r.alertas_abiertas;
  $('#k-criticas').textContent = r.alertas_criticas;
  $('#k-politica').textContent = 'v' + r.version_politica;
}

// ── Topologia ───────────────────────────────────────────────────────────

async function cargarFlota() {
  try {
    const lista = await api('/api/agentes?limite=1000');
    app.agentes = new Map(lista.map((a) => [a.cn, a]));
    if (app.vista === 'topologia') pintarFlota();
  } catch (_) { /* ya avisado */ }
}

$('#solo-problemas').addEventListener('change', pintarFlota);

function pintarFlota() {
  const rejilla = $('#rejilla-flota');
  const soloProblemas = $('#solo-problemas').checked;
  rejilla.textContent = '';

  let agentes = Array.from(app.agentes.values());
  if (soloProblemas) {
    agentes = agentes.filter((a) => !a.en_linea || a.aislado || a.amenazas_activas > 0);
  }
  $('#flota-vacia').hidden = agentes.length > 0;

  // Lo que exige atencion, primero: aislados, luego amenazados, luego caidos.
  agentes.sort((a, b) => rango(b) - rango(a) || a.hostname.localeCompare(b.hostname));

  for (const a of agentes) {
    const el = document.createElement('div');
    el.className = 'nodo ' + claseNodo(a);
    el.tabIndex = 0;
    const visto = a.ultimo_latido
      ? new Date(a.ultimo_latido).toLocaleTimeString('es-ES', { hour12: false })
      : 'nunca';
    el.innerHTML =
      `<div class="host"></div><div class="cn"></div>` +
      `<div class="metricas"><span>RSS ${Math.round(a.rss_kb / 1024)} MB</span>` +
      `<span>${a.amenazas_activas} amenaza(s)</span><span>${visto}</span></div>` +
      (a.aislado ? '<span class="etiqueta">AISLADO</span>' : '');
    // textContent y no innerHTML para el hostname y el CN: los declara el
    // endpoint, y un endpoint comprometido no va a inyectar marcado en la
    // consola de quien lo investiga.
    el.querySelector('.host').textContent = a.hostname || '(sin nombre)';
    el.querySelector('.cn').textContent = a.cn;
    el.addEventListener('click', () => abrirEndpoint(a.cn));
    rejilla.appendChild(el);
  }
}

function rango(a) {
  if (a.aislado) return 3;
  if (a.amenazas_activas > 0) return 2;
  if (!a.en_linea) return 1;
  return 0;
}

function claseNodo(a) {
  if (a.aislado) return 'aislado';
  if (a.amenazas_activas > 0) return 'amenazado';
  return a.en_linea ? 'en-linea' : 'caido';
}

// ── Respuesta de un clic ────────────────────────────────────────────────

async function abrirEndpoint(cn) {
  let a;
  try { a = await api('/api/agentes/' + encodeURIComponent(cn)); }
  catch (ex) { return alert(ex.message); }

  app.seleccionado = a;
  $('#modal-titulo').textContent = a.hostname || a.cn;
  const dl = $('#modal-datos');
  dl.textContent = '';
  const filas = [
    ['Identidad (CN)', a.cn],
    ['Versión del agente', a.version_agente],
    ['Estado', a.en_linea ? 'en línea' : 'sin latidos'],
    ['Aislado', a.aislado ? 'sí' : 'no'],
    ['Memoria', Math.round(a.rss_kb / 1024) + ' MB'],
    ['Amenazas activas', String(a.amenazas_activas)],
    ['Latidos / eventos', `${a.latidos} / ${a.eventos}`],
    ['Política aplicada', 'v' + a.version_politica],
  ];
  for (const [k, v] of filas) {
    const dt = document.createElement('dt'); dt.textContent = k;
    const dd = document.createElement('dd'); dd.textContent = v;
    dl.append(dt, dd);
  }
  $('#modal-aviso').textContent = a.aislado
    ? 'Este endpoint está aislado: sigue reportando, pero su política local le corta el resto de la red.'
    : 'Aislar corta la conectividad de red del endpoint salvo con el plano de control. El agente lo aplica en su próximo contacto; queda registrado con tu usuario.';
  $('#btn-aislar').hidden = a.aislado;
  $('#btn-liberar').hidden = !a.aislado;
  $('#modal').hidden = false;
}

$('#btn-cerrar').addEventListener('click', () => { $('#modal').hidden = true; });
$('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') $('#modal').hidden = true; });

$('#btn-aislar').addEventListener('click', () => responder('aislar'));
$('#btn-liberar').addEventListener('click', () => responder('liberar'));

async function responder(accion) {
  const a = app.seleccionado;
  if (!a) return;
  // Una accion que corta la red de una maquina de produccion se confirma. No
  // por burocracia: por un clic de mas en la tarjeta equivocada.
  const texto = accion === 'aislar'
    ? `¿Aislar «${a.hostname || a.cn}» de la red?`
    : `¿Devolver «${a.hostname || a.cn}» a la red?`;
  if (!confirm(texto)) return;
  try {
    await api(`/api/agentes/${encodeURIComponent(a.cn)}/${accion}`, { method: 'POST' });
    $('#modal').hidden = true;
    cargarFlota();
  } catch (ex) { alert(ex.message); }
}

// ── Alertas ─────────────────────────────────────────────────────────────

$('#solo-abiertas').addEventListener('change', cargarAlertas);

async function cargarAlertas() {
  const abiertas = $('#solo-abiertas').checked;
  let lista;
  try { lista = await api(`/api/alertas?limite=300&abiertas=${abiertas}`); }
  catch (_) { return; }

  const tb = $('#tabla-alertas').querySelector('tbody');
  tb.textContent = '';
  $('#alertas-vacio').hidden = lista.length > 0;

  for (const x of lista) {
    const tr = document.createElement('tr');
    tr.appendChild(celda(`<span class="sev sev-${x.severidad}">${x.severidad}</span>`, true));
    tr.appendChild(celdaTexto(corto(x.cn_agente), 'mono'));
    tr.appendChild(celdaTexto(x.categoria));
    tr.appendChild(celda(x.tecnica_mitre
      ? `<span class="tecnica">${escape(x.tecnica_mitre)}</span> ${escape(x.tactica_mitre || '')}`
      : '<span style="color:var(--texto-2)">sin mapeo</span>', true));
    tr.appendChild(celdaTexto(x.descripcion));
    tr.appendChild(celdaTexto(new Date(x.recibido_en).toLocaleString('es-ES', { hour12: false })));
    tb.appendChild(tr);
  }
}

function celdaTexto(texto, clase) {
  const td = document.createElement('td');
  if (clase) td.className = clase;
  td.textContent = texto;   // nunca innerHTML con datos del endpoint
  return td;
}
function celda(html, confiable) {
  const td = document.createElement('td');
  if (confiable) td.innerHTML = html; else td.textContent = html;
  return td;
}
function escape(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ── Linaje de procesos ──────────────────────────────────────────────────

async function cargarGrafos() {
  let lista;
  try { lista = await api('/api/grafos?limite=100'); } catch (_) { return; }
  const sel = $('#selector-grafo');
  sel.textContent = '';
  if (lista.length === 0) {
    const o = document.createElement('option');
    o.textContent = 'sin linajes capturados';
    sel.appendChild(o);
    $('#lienzo-arbol').textContent = '';
    return;
  }
  for (const g of lista) {
    const o = document.createElement('option');
    o.value = g.id;
    o.textContent = `${new Date(g.recibido_en).toLocaleString('es-ES', { hour12: false })}` +
      ` · ${corto(g.cn_agente)} · ${g.nodos} nodo(s)`;
    sel.appendChild(o);
  }
  sel.value = app.grafoActual || lista[0].id;
  dibujarGrafo(sel.value);
}

$('#selector-grafo').addEventListener('change', (e) => dibujarGrafo(e.target.value));

async function dibujarGrafo(id) {
  if (!id) return;
  app.grafoActual = id;
  let datos;
  try { datos = await api('/api/grafos/' + encodeURIComponent(id)); } catch (_) { return; }
  pintarArbol(datos.nodos);
}

/**
 * Dibuja el arbol de linaje en SVG.
 *
 * La disposicion es por niveles: la profundidad manda en el eje vertical y los
 * hermanos se reparten en el horizontal. Para un linaje de procesos —pocos
 * nodos, muy jerarquico— eso se lee de un vistazo, que es de lo que se trata.
 */
function pintarArbol(nodos) {
  const lienzo = $('#lienzo-arbol');
  lienzo.textContent = '';
  $('#detalle-nodo').hidden = true;
  if (!nodos || nodos.length === 0) return;

  const ANCHO = 240, ALTO = 46, SEP_X = 24, SEP_Y = 74, MARGEN = 24;

  // Agrupar por profundidad, respetando el orden que envio el servidor.
  const niveles = new Map();
  for (const n of nodos) {
    if (!niveles.has(n.profundidad)) niveles.set(n.profundidad, []);
    niveles.get(n.profundidad).push(n);
  }
  const profundidades = Array.from(niveles.keys()).sort((a, b) => a - b);

  const pos = new Map();
  let anchoTotal = 0;
  for (const d of profundidades) {
    const fila = niveles.get(d);
    const ancho = fila.length * ANCHO + (fila.length - 1) * SEP_X;
    anchoTotal = Math.max(anchoTotal, ancho);
    fila.forEach((n, i) => {
      pos.set(String(n.clave), {
        x: MARGEN + i * (ANCHO + SEP_X),
        y: MARGEN + profundidades.indexOf(d) * SEP_Y,
        n,
      });
    });
  }

  const w = anchoTotal + MARGEN * 2;
  const h = profundidades.length * SEP_Y + MARGEN * 2;
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('width', Math.max(w, 600));
  svg.setAttribute('height', h);

  // Aristas primero, para que queden por debajo de las cajas.
  for (const { x, y, n } of pos.values()) {
    const p = pos.get(String(n.padre));
    if (!p) continue;
    const path = document.createElementNS(NS, 'path');
    const x1 = p.x + ANCHO / 2, y1 = p.y + ALTO;
    const x2 = x + ANCHO / 2, y2 = y;
    const ym = (y1 + y2) / 2;
    path.setAttribute('d', `M${x1},${y1} C${x1},${ym} ${x2},${ym} ${x2},${y2}`);
    path.setAttribute('class', 'arista');
    svg.appendChild(path);
  }

  for (const { x, y, n } of pos.values()) {
    const g = document.createElementNS(NS, 'g');

    const caja = document.createElementNS(NS, 'rect');
    caja.setAttribute('x', x); caja.setAttribute('y', y);
    caja.setAttribute('width', ANCHO); caja.setAttribute('height', ALTO);
    let clase = 'caja-proc';
    if (n.taints !== 0) clase += ' contaminado';
    if (n.puntuacion >= 70) clase += ' raiz';
    caja.setAttribute('class', clase);
    g.appendChild(caja);

    const nombre = document.createElementNS(NS, 'text');
    nombre.setAttribute('x', x + 10); nombre.setAttribute('y', y + 19);
    nombre.setAttribute('class', 'txt-proc');
    nombre.textContent = recortar(n.imagen.split('/').pop() || n.imagen, 26);
    g.appendChild(nombre);

    const pid = document.createElementNS(NS, 'text');
    pid.setAttribute('x', x + 10); pid.setAttribute('y', y + 35);
    pid.setAttribute('class', 'txt-pid');
    pid.textContent = `pid ${n.pid} · clave ${n.clave}`;
    g.appendChild(pid);

    if (n.puntuacion > 0) {
      const s = document.createElementNS(NS, 'text');
      s.setAttribute('x', x + ANCHO - 10); s.setAttribute('y', y + 19);
      s.setAttribute('text-anchor', 'end');
      s.setAttribute('class', 'txt-score');
      s.setAttribute('fill', n.puntuacion >= 70 ? 'var(--grave)' : 'var(--aviso)');
      s.textContent = n.puntuacion;
      g.appendChild(s);
    }

    g.addEventListener('click', () => detallarNodo(n));
    svg.appendChild(g);
  }

  lienzo.appendChild(svg);
}

function recortar(s, max) { return s.length > max ? s.slice(0, max - 1) + '…' : s; }

function detallarNodo(n) {
  const d = $('#detalle-nodo');
  d.textContent = '';
  const filas = [
    ['imagen', n.imagen],
    ['línea de comandos', n.cmdline],
    ['clave estable', String(n.clave)],
    ['pid', String(n.pid)],
    ['padre / creador', `${n.padre} / ${n.creador}`],
    ['profundidad', String(n.profundidad)],
    ['marcas de contaminación', '0b' + (n.taints >>> 0).toString(2)],
    ['puntuación', String(n.puntuacion)],
    ['estado', n.terminado_ns ? 'terminado' : 'vivo al capturar'],
  ];
  for (const [k, v] of filas) {
    const linea = document.createElement('div');
    const et = document.createElement('span');
    et.style.color = 'var(--texto-2)';
    et.textContent = k + ': ';
    linea.appendChild(et);
    linea.appendChild(document.createTextNode(v));
    d.appendChild(linea);
  }
  d.hidden = false;
}

// ── Reglas globales ─────────────────────────────────────────────────────

const CAMPO_DE_TIPO = {
  bloquear_puerto: ['puerto', 'número', (v) => ({ puerto: Number(v) })],
  bloquear_hash: ['sha256', '64 hex', (v) => ({ sha256: v })],
  bloquear_proceso: ['imagen', '/ruta/absoluta', (v) => ({ imagen: v })],
  bloquear_red: ['cidr', '10.0.0.0/8', (v) => ({ cidr: v })],
  aislar_por_puntuacion: ['umbral', '1..1000', (v) => ({ umbral: Number(v) })],
};

$('#r-tipo').addEventListener('change', (e) => {
  const [, ejemplo] = CAMPO_DE_TIPO[e.target.value];
  $('#r-valor').placeholder = ejemplo;
  $('#r-valor').value = '';
});

$('#form-regla').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#error-regla');
  err.hidden = true;
  const tipo = $('#r-tipo').value;
  const [, , construir] = CAMPO_DE_TIPO[tipo];
  try {
    await api('/api/reglas', {
      method: 'POST',
      body: JSON.stringify({
        nombre: $('#r-nombre').value.trim(),
        tipo,
        parametros: construir($('#r-valor').value.trim()),
        severidad: Number($('#r-sev').value),
      }),
    });
    $('#r-nombre').value = ''; $('#r-valor').value = '';
    cargarReglas();
  } catch (ex) {
    // El servidor valida y explica la CONSECUENCIA, no solo el rango: se
    // muestra tal cual, que es lo util para quien la escribe.
    err.textContent = ex.message;
    err.hidden = false;
  }
});

async function cargarReglas() {
  let lista;
  try { lista = await api('/api/reglas'); } catch (_) { return; }
  const tb = $('#tabla-reglas').querySelector('tbody');
  tb.textContent = '';
  for (const r of lista) {
    const tr = document.createElement('tr');
    tr.appendChild(celda(r.activa
      ? '<span class="sev sev-2">ON</span>'
      : '<span class="sev sev-0">off</span>', true));
    tr.appendChild(celdaTexto(r.nombre));
    tr.appendChild(celdaTexto(r.tipo));
    tr.appendChild(celdaTexto(JSON.stringify(r.parametros), 'mono'));
    tr.appendChild(celda(`<span class="sev sev-${r.severidad}">${r.severidad}</span>`, true));
    tr.appendChild(celdaTexto(r.creada_por));

    const td = document.createElement('td');
    const alternar = document.createElement('button');
    alternar.className = 'secundario';
    alternar.textContent = r.activa ? 'Desactivar' : 'Activar';
    alternar.addEventListener('click', async () => {
      try {
        await api(`/api/reglas/${r.id}/activa`, {
          method: 'POST', body: JSON.stringify({ activa: !r.activa }),
        });
        cargarReglas();
      } catch (ex) { alert(ex.message); }
    });
    const borrar = document.createElement('button');
    borrar.className = 'secundario';
    borrar.textContent = 'Borrar';
    borrar.style.marginLeft = '6px';
    borrar.addEventListener('click', async () => {
      if (!confirm(`¿Retirar la regla «${r.nombre}» de toda la flota?`)) return;
      try {
        await api('/api/reglas/' + r.id, { method: 'DELETE' });
        cargarReglas();
      } catch (ex) { alert(ex.message); }
    });
    td.append(alternar, borrar);
    tr.appendChild(td);
    tb.appendChild(tr);
  }
}

// ── Inteligencia ────────────────────────────────────────────────────────

async function cargarStix() {
  let lista;
  try { lista = await api('/api/stix/objetos?limite=200'); } catch (_) { return; }
  const tb = $('#tabla-stix').querySelector('tbody');
  tb.textContent = '';
  $('#stix-vacio').hidden = lista.length > 0;
  for (const o of lista) {
    const tr = document.createElement('tr');
    tr.appendChild(celdaTexto(String(o.avistamientos)));
    tr.appendChild(celdaTexto(o.tipo));
    tr.appendChild(celdaTexto(recortar(o.id, 44), 'mono'));
    const c = o.contenido || {};
    tr.appendChild(celdaTexto(recortar(c.pattern || c.command_line || c.name || '—', 60)));
    tr.appendChild(celdaTexto(new Date(o.ultima_vez).toLocaleString('es-ES', { hour12: false })));
    tb.appendChild(tr);
  }
}

// ── Arranque ────────────────────────────────────────────────────────────

$('#r-valor').placeholder = CAMPO_DE_TIPO.bloquear_puerto[1];
if (app.token) entrar(); else $('#acceso').hidden = false;
