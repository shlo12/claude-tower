const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const SEV = {
  critical: { label: '高危', color: '#d92d20' },
  high: { label: '偏高', color: '#ef6820' },
  medium: { label: '中等', color: '#d99a00' },
  low: { label: '偏低', color: '#667085' },
  info: { label: '信息', color: '#98a2b3' },
  pass: { label: '通过', color: '#12b76a' },
};

const state = {
  scan: null, filter: 'all', q: '', open: new Set(), sel: new Set(), plan: null, busy: false, home: '',
  unlocked: undefined,   // undefined=还没拿到塔的数据；true/false=是否已闯过关
};

// 魔镜/分身/心魔：闯过至少一关之后才开放
const GATED_TABS = new Set(['findings', 'clean', 'isolation', 'checklist']);

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const shortPath = (p) => (state.home && String(p).startsWith(state.home) ? '~' + String(p).slice(state.home.length) : String(p));

function fmtSize(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i <= 1 ? Math.round(n) : n.toFixed(1)} ${u[i]}`;
}

function toast(msg, ms = 2800) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), ms);
}

// 服务端每次启动生成一个新令牌，直接写进 index.html 的 meta 里。
// 每个 /api/ 请求都要带上它；跨站页面设不了自定义头（会被预检拦住）。
const CC_TOKEN = (document.querySelector('meta[name="cc-token"]') || {}).content || '';
function ccHeaders(extra) {
  return Object.assign({ 'X-CClean-Token': CC_TOKEN }, extra || {});
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: ccHeaders({ 'Content-Type': 'application/json', ...(opts.headers || {}) }),
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.error) throw new Error(data.error || `请求失败 (${res.status})`);
  return data;
}

/* ============================================================ 对外接口 */

function setScan(scan) {
  state.scan = scan;
  // 新结果一到，旧勾选全部作废：检测项可能已经不在了，留着就是幽灵选中。
  state.sel.clear();
  renderScan(scan);
  renderFindings();
}

function setUnlocked(u) {
  const was = state.unlocked;
  state.unlocked = u;
  document.body.classList.toggle('tools-open', !!u);
  if (!u) {
    const cur = $('.tab.active');
    if (cur && GATED_TABS.has(cur.dataset.tab)) switchTab('settle');
  }
  if (was === false && u === true) {
    setTimeout(() => toast('新区域开放：魔镜 · 分身术 · 心魔试炼', 4800), 900);
    $$('.tab[data-gated]').forEach((t, i) => {
      setTimeout(() => {
        t.classList.add('just-open');
        setTimeout(() => t.classList.remove('just-open'), 1400);
      }, i * 140);
    });
  }
}

/* 把 ids 放进待清理清单。

   默认 replace=true，用于「一键修改」这类用户主动按下整批入口的按钮；
   replace=false 用于逐项勾选时的追加。无论哪种，都只处理传进来的 id——
   没有任何地方会替用户预选，state.sel 的初始值就是空集合。 */
function selectForClean(ids, { replace = true, open = true } = {}) {
  const allowed = new Set(fixableItems().map((i) => i.id));
  const use = [...new Set(ids || [])].filter((id) => allowed.has(id));
  if (!use.length) return 0;
  state.sel = replace ? new Set(use) : new Set([...state.sel, ...use]);
  updatePickBar();
  if (open) openModal();
  return use.length;
}

/* 单项勾选/取消。永远由用户点击触发。 */
function togglePick(id) {
  if (!id) return;
  if (state.sel.has(id)) state.sel.delete(id);
  else state.sel.add(id);
  updatePickBar();
}

/* 底部选择条：只同步计数与每行的勾选态，不重排列表（否则滚动位置会跳）。 */
function updatePickBar() {
  const bar = $('#pickbar');
  if (!bar) return;
  const total = fixableItems().length;
  bar.hidden = total === 0;
  const n = state.sel.size;
  $('#pick-count').textContent = String(n);
  $('#pick-sum').textContent = total ? `可自动处理 ${total} 项` : '';
  const go = $('#pick-go');
  go.disabled = n === 0;
  go.textContent = n ? `确认清理（${n} 项）` : '确认清理';
  $$('.row[data-id]').forEach((row) => {
    const b = row.querySelector('[data-pick]');
    if (!b) return;
    const on = state.sel.has(row.dataset.id);
    b.classList.toggle('on', on);
    b.setAttribute('aria-pressed', String(on));
  });
}

window.CC = { api, ccHeaders, token: CC_TOKEN, toast, esc, switchTab, setScan, setUnlocked, state, $, $$, fmtSize, shortPath, SEV, selectForClean, togglePick, updatePickBar, runWebrtcProbe };


/* ============================================================ 扫描渲染 */

function skeleton() {
  return `<div class="list" style="padding:16px">
    ${Array.from({ length: 5 }, (_, i) => `<div style="display:flex;gap:12px;align-items:center;margin-bottom:14px">
      <div class="skeleton" style="width:3px;height:34px"></div>
      <div style="flex:1"><div class="skeleton" style="height:11px;width:${38 + i * 9}%;margin-bottom:7px"></div>
      <div class="skeleton" style="height:9px;width:${62 - i * 5}%"></div></div></div>`).join('')}
  </div>`;
}

function ringColor(score) {
  if (score >= 90) return '#4fbf7a';
  if (score >= 80) return '#e0b45c';
  if (score >= 65) return '#d9a94a';
  if (score >= 50) return '#e8813a';
  return '#e05252';
}

function renderScan(d) {
  const C = 2 * Math.PI * 72;
  const val = $('#ring-val');
  val.style.stroke = ringColor(d.score);
  const ratio = Math.max(0.025, d.score / 100);
  requestAnimationFrame(() => {
    val.style.strokeDashoffset = String(C * (1 - ratio));
  });
  $('#score-num').textContent = d.score;
  $('#grade').textContent = `${d.grade} 级`;
  $('#grade').className = 'grade ' + String(d.grade || '').toLowerCase();
  $('#verdict').textContent = d.verdict;
  $('#verdict-text').textContent = d.verdictText;

  const order = ['critical', 'high', 'medium', 'low', 'pass'];
  $('#chips').innerHTML = order
    .filter((k) => d.counts[k])
    .map((k) => `<span class="chip"><span class="dot" style="background:${SEV[k].color}"></span>${SEV[k].label} <b>${d.counts[k]}</b></span>`)
    .join('') || '<span class="chip">无异常项</span>';

  const net = d.network || {};
  $('#meta-ip').textContent = net.available ? `${net.ip}${net.country ? ' · ' + net.country : ''}` : '未探测';
  $('#meta-ip').title = net.available ? `${net.org || ''} ${net.asn_type || ''}`.trim() : '';
  $('#meta-tz').textContent = d.system.timezone;
  $('#meta-time').textContent = d.scannedAt.slice(11);

  $('#tab-n-find').textContent = d.items.filter((i) => i.severity !== 'pass' && i.severity !== 'info').length;
}

/* ============================================================ 检测结果 */

const CAT_ORDER = ['fingerprint', 'credential', 'marker', 'locale', 'network', 'residue', 'device', 'behavior'];

function renderFindings() {
  refreshWatch();
  const d = state.scan;
  if (!d) return;
  const box = $('#findings');

  let items = d.items.filter((it) => {
    if (state.filter === 'privacy') return (it.tags || []).includes('privacy');
    if (state.filter === 'risk') return ['critical', 'high', 'medium'].includes(it.severity);
    if (state.filter !== 'all') return it.severity === state.filter;
    return true;
  });
  if (state.q) {
    const q = state.q.toLowerCase();
    items = items.filter((it) => (it.title + it.detail + it.advice + JSON.stringify(it.evidence)).toLowerCase().includes(q));
  }

  if (!items.length) {
    box.innerHTML = `<div class="card"><div class="empty"><svg><use href="#i-empty"/></svg><p>这一面镜子里没有东西</p></div></div>`;
    updatePickBar();
    return;
  }

  const groups = {};
  for (const it of items) (groups[it.category] = groups[it.category] || []).push(it);

  box.innerHTML = CAT_ORDER.filter((c) => groups[c]).map((cat) => {
    const meta = d.categories[cat] || { label: cat, desc: '' };
    const rows = groups[cat].map(rowHtml).join('');
    return `<section class="cat">
      <div class="cat-head"><h3>${esc(meta.label)}</h3><span class="cnt">${groups[cat].length}</span>
      <span class="desc">${esc(meta.desc)}</span></div>
      <div class="list">${rows}</div>
    </section>`;
  }).join('');
  updatePickBar();
}

function rowHtml(it) {
  const s = SEV[it.severity] || SEV.info;
  const open = state.open.has(it.id) ? ' open' : '';
  const ev = it.evidence.length
    ? `<div class="ev-grid">${it.evidence.map((e) =>
        `<div class="ev"><span class="k">${esc(e.label)}</span><span class="v${e.mono ? ' mono' : ''}">${esc(e.value)}</span></div>`).join('')}</div>`
    : '';
  const advice = it.advice ? `<div class="advice"><b>建议</b> · ${esc(it.advice)}</div>` : '';
  const manual = it.fix && it.fix.kind === 'manual';
  const fixable = it.fix && it.fix.kind !== 'manual';
  // 需要在浏览器里跑一段才能测的项目（目前只有浏览器侧 WebRTC）
  const probe = it.probe ? `<button class="btn sm" data-probe="${esc(it.probe)}">在本机浏览器里实测</button>` : '';
  const actions = (fixable || manual || probe)
    ? `<div class="row-actions">
        ${fixable ? `<button class="btn sm" data-fix="${esc(it.id)}">${(it.tags || []).includes('privacy') ? '预览关闭方案' : '加入清理清单'}</button>` : ''}
        ${probe}
        ${manual && it.fix.command ? `<button class="btn sm ghost" data-copy="${esc(it.fix.command)}">复制命令</button>
          <span class="hint">需要手动执行</span>` : ''}
      </div>` : '';

  // 勾选态一律从 state.sel 里读，永远不预置——默认就是空集合。
  const picked = state.sel.has(it.id);
  const pick = fixable
    ? `<button class="pick${picked ? ' on' : ''}" data-pick="${esc(it.id)}"
         aria-pressed="${picked}" title="选中这一项（默认不选）"><svg><use href="#i-check"/></svg></button>`
    : `<span class="pick pick-blank" aria-hidden="true"></span>`;

  return `<div class="row${open}" data-id="${esc(it.id)}" data-sev="${it.severity}">
    ${pick}
    <div class="sev-bar"></div>
    <div class="row-main">
      <div class="row-top">
        <span class="row-title">${esc(it.title)}</span>
        <span class="badge ${it.severity}">${s.label}</span>
      </div>
      <div class="row-detail">${esc(it.detail)}</div>
      <div class="row-more">${ev}${advice}${actions}</div>
    </div>
    <div class="chev"><svg><use href="#i-chev"/></svg></div>
  </div>`;
}

/* ============================================================ 清理 */

function fixableItems() {
  if (!state.scan) return [];
  return state.scan.items.filter((i) => i.fix && i.fix.kind !== 'manual');
}

/* ============================================================ 弹层 */

function openModal({ keepConfirm = false } = {}) {
  const ids = [...state.sel];
  if (!ids.length) return;
  $('#modal-title').textContent = '确认清理';
  $('#modal-sub').innerHTML = '缓存、诊断日志、密钥与令牌不保留副本，不进废纸篓，无法还原；其他项目按下方说明处理。清理凭据后需要重新登录。每一行都可以单独去掉。';
  if (!keepConfirm) {
    $('#confirm-input').value = '';
    $('#modal-go').disabled = true;
  }
  $('#confirm-box').style.display = '';
  $('#modal-go').textContent = '确认清理';
  $('#modal-go').dataset.mode = 'clean';
  $('#modal').classList.add('show');

  api('/api/preview', { method: 'POST', body: { ids } }).then(({ plan, running }) => {
    state.plan = plan;
    state.running = running || [];
    const warns = (plan.warnings || []).map((w) => `<div class="res-item bad">
          <span class="ic">⚠</span>
          <span><div>${esc(w)}</div></span>
        </div>`).join('');
    const warn = state.running.length
      ? `<div class="res-item bad" id="modal-running">
          <span class="ic">⚠</span>
          <span><div>有 ${state.running.length} 个 claude 进程正在运行</div>
          <div class="ci-path">${esc(state.running.map((p) => p.name).join('；'))} —— 运行中的客户端会把指纹/会话写回去，建议先退出</div></span>
        </div>
        <button class="btn sm" id="modal-kill" style="margin:0 0 8px 30px">先退出这些进程</button>` : '';
    const rows = plan.ops.map((op) => `<div class="res-item">
        <span class="ic" style="color:var(--text-3)"><svg width="15" height="15"><use href="#i-box"/></svg></span>
        <span><div>${esc(op.title)}</div>
          <div class="ci-path">${esc(op.display)}</div>
          <div class="ci-risk">${op.retention === 'no-copy' ? '不留副本 · 不可还原' : op.retention === 'filtered' ? '过滤后保留 · 敏感内容不可还原' : '按清单保留可恢复内容'}</div>
          ${op.risk ? `<div class="ci-risk">⚠ ${esc(op.risk)}</div>` : ''}
          ${op.manual ? `<div class="ci-manual">${esc(op.manual)}</div>` : ''}
        </span>
        <button class="op-drop" data-unpick="${esc(op.id)}" title="这一项不处理了">×</button>
      </div>`).join('');
    const skip = plan.skipped.length
      ? `<div class="divider"></div><div style="font-size:12px;color:var(--text-3);margin-bottom:6px">跳过 ${plan.skipped.length} 项</div>` +
        plan.skipped.map((s) => `<div class="res-item"><span class="ic" style="color:var(--text-3)">·</span>
          <span><div>${esc(s.title || s.id)}</div><div class="ci-path">${esc(s.reason)}${s.command ? ' · ' + esc(s.command) : ''}</div></span></div>`).join('')
      : '';
    const noop = plan.ops.length ? '' : `<div class="res-item bad"><span class="ic">!</span>
        <span><div>这些条目都没有可自动执行的操作</div>
        <div class="ci-path">看下面的跳过原因，按建议手动处理，或者取消后重新勾选</div></span></div>`;
    $('#modal-list').innerHTML = warns + warn + rows + noop + skip +
      `<div class="divider"></div><div class="sum-row"><span class="k">合计</span>
       <span class="v">${plan.ops.length} 项 · ${plan.totalFiles} 个文件 · ${fmtSize(plan.totalBytes)}</span></div>`;
  }).catch((e) => {
    $('#modal-list').innerHTML = `<div class="res-item bad"><span class="ic">!</span><span>${esc(e.message)}</span></div>`;
  });
}

/* 清理弹层里的「先退出这些进程」+ 逐项移除 */
$('#modal-list').addEventListener('click', async (e) => {
  const drop = e.target.closest('[data-unpick]');
  if (drop) {
    state.sel.delete(drop.dataset.unpick);
    updatePickBar();
    if (!state.sel.size) {
      closeModal();
      toast('清单已经清空，什么都不会动');
      return;
    }
    openModal({ keepConfirm: true });
    return;
  }
  if (!e.target.closest('#modal-kill')) return;
  const btn = $('#modal-kill');
  btn.disabled = true;
  btn.textContent = '正在退出…';
  try {
    const r = await api('/api/kill-claude', { method: 'POST', body: {} });
    const warn = $('#modal-running');
    if (r.left && r.left.length) {
      btn.textContent = `还有 ${r.left.length} 个退不掉`;
      toast('有进程退不掉，清理结果可能被回写', 4200);
    } else {
      if (warn) warn.remove();
      btn.remove();
      toast('claude 进程已全部退出', 2400);
    }
  } catch (err) {
    btn.disabled = false;
    btn.textContent = '先退出这些进程';
    toast(err.message);
  }
});

function closeModal() {
  $('#modal').classList.remove('show');
}

async function doClean() {
  const ids = [...state.sel];
  const go = $('#modal-go');
  go.disabled = true;
  go.textContent = '执行中…';
  try {
    const { result } = await api('/api/clean', { method: 'POST', body: { ids, confirm: $('#confirm-input').value.trim().toUpperCase() } });
    $('#modal-title').textContent = result.ok ? '清理完成' : '清理未完成';
    $('#modal-sub').textContent = result.message;
    $('#confirm-box').style.display = 'none';
    $('#modal-list').innerHTML = result.results.map((r) => `<div class="res-item ${r.ok ? 'ok' : 'bad'}">
        <span class="ic">${r.ok ? '✓' : '✕'}</span>
        <span><div>${esc(r.title)}</div><div class="ci-path">${esc(r.message)}</div></span>
      </div>`).join('') +
      `<div class="divider"></div>
       <div style="font-size:12px;color:var(--text-2);line-height:1.7">
         ${result.backupDir ? `清理记录：<code>${esc(result.backupDir)}</code><br>` : ''}
         ${result.trashDir ? `回收区：<code>${esc(result.trashDir)}</code><br>` : ''}
         <span style="color:var(--text-3)">${esc(result.restoreHint || '')}</span>
       </div>`;
    go.textContent = '关闭';
    go.disabled = false;
    go.dataset.mode = 'done';
    state.sel.clear();
    toast(result.message);
  } catch (e) {
    go.textContent = '重试';
    go.disabled = false;
    toast(e.message);
  }
}

/* ============================================================ 隔离环境 */

async function loadProfiles() {
  try {
    const { profiles } = await api('/api/profiles');
    $('#pf-count').textContent = `${profiles.length} 个`;
    const box = $('#profile-list');
    if (!profiles.length) {
      box.innerHTML = `<div class="empty"><p>还没有铸造过分身</p></div>`;
      return;
    }
    box.innerHTML = profiles.map((p) => `<div class="profile">
      <div class="picon"><svg><use href="#i-shield"/></svg></div>
      <div style="min-width:0;flex:1">
        <div class="pname">${esc(p.name)}</div>
        <div class="pmeta">${esc(p.timezone)} · ${esc(p.configDir)}</div>
      </div>
      <button class="btn sm" data-copy="sh ${esc(p.script)}">复制启动命令</button>
      <button class="btn sm ghost" data-del="${esc(p.slug)}" title="删除配置档，不留副本"><svg width="14" height="14"><use href="#i-x"/></svg></button>
    </div>`).join('');
  } catch (e) {
    toast(e.message);
  }
}

async function createProfile() {
  const name = $('#pf-name').value.trim();
  if (!name) { toast('先给配置档起个名字'); return; }
  const btn = $('#btn-profile');
  btn.disabled = true;
  try {
    const res = await api('/api/profiles', {
      method: 'POST',
      body: { name, tz: $('#pf-tz').value.trim() || 'UTC', baseUrl: $('#pf-url').value.trim(), docker: $('#pf-docker').checked },
    });
    $('#pf-name').value = '';
    $('#pf-url').value = '';
    await loadProfiles();
    toast('已生成：' + res.runCommand);
  } catch (e) {
    toast(e.message);
  } finally {
    btn.disabled = false;
  }
}

/* ============================================================ 清单 */

let ckDone = new Set();
let ckTotal = 0;

async function loadChecklist() {
  try {
    const data = await api('/api/checklist');
    ckDone = new Set(data.done || []);
    ckTotal = data.total;
    const box = $('#checklist');
    box.innerHTML = data.groups.map((g) => `<section class="ck-group">
      <div class="ck-head"><h3>${esc(g.title)}</h3><span>${esc(g.hint)}</span></div>
      <div class="list">${g.items.map((it) => {
        const done = ckDone.has(it.id) ? ' done' : '';
        return `<label class="ck-item${done}" data-id="${esc(it.id)}">
          <span class="cbox"><svg><use href="#i-check"/></svg></span>
          <span><div class="ck-text">${esc(it.text)}</div><div class="ck-why">${esc(it.why)}</div></span>
        </label>`;
      }).join('')}</div>
    </section>`).join('');
    updateCk();
  } catch (e) {
    toast(e.message);
  }
}

function updateCk() {
  const n = ckDone.size;
  $('#ck-num').textContent = `${n} / ${ckTotal}`;
  $('#ck-bar').style.width = `${ckTotal ? (n / ckTotal) * 100 : 0}%`;
}

let ckTimer = null;
function syncChecklist() {
  clearTimeout(ckTimer);
  ckTimer = setTimeout(() => {
    api('/api/wizard/progress', { method: 'POST', body: { checklist: [...ckDone] } }).catch(() => {});
  }, 250);
}

/* ============================================================ 浏览器侧 WebRTC 实测 */

// 候选地址只能由浏览器自己给。走 ICE 收集而不是 getUserMedia：
// 不碰摄像头，就不会弹授权框，也不需要用户点两次。
const PROBE_ICE = [
  { urls: 'stun:stun.miwifi.com:3478' },
  { urls: 'stun:stun.qq.com:3478' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun.nextcloud.com:443' },
];

async function runWebrtcProbe() {
  if (!window.RTCPeerConnection) { toast('这个浏览器不支持 WebRTC'); return; }
  toast('正在收集 ICE 候选，大约 6 秒…', 6500);
  const cands = [];
  let pc = null;
  try {
    pc = new RTCPeerConnection({ iceServers: PROBE_ICE });
    pc.createDataChannel('ccclean-probe');
    pc.onicecandidate = (e) => { if (e.candidate && e.candidate.candidate) cands.push(e.candidate.candidate); };
    await pc.setLocalDescription(await pc.createOffer());
    // 收集结束有两种信号：icegatheringstate 变 complete，或 onicecandidate 收到 null。
    // Safari 上两者都可能迟到，所以再加一个固定上限兜底——没有上限就等于挂死在这里。
    await new Promise((resolve) => {
      let done = false;
      const finish = () => { if (!done) { done = true; resolve(); } };
      pc.addEventListener('icegatheringstatechange', () => {
        if (pc.iceGatheringState === 'complete') finish();
      });
      pc.addEventListener('icecandidate', (e) => { if (!e.candidate) finish(); });
      setTimeout(finish, 6000);
    });
  } catch (e) {
    toast('WebRTC 探测失败：' + e.message);
    return;
  } finally {
    if (pc) pc.close();
  }

  try {
    const d = await api('/api/probe/webrtc', {
      method: 'POST',
      body: { candidates: cands, ua: navigator.userAgent },
    });
    toast((d.verdict && d.verdict.title) || '实测完成', 4000);
    // 结论变了要重算分数与关卡，所以这里必须真的重扫一次
    if (window.Tower) await Tower.reload(true);
  } catch (e) {
    toast(e.message);
  }
}

/* ============================================================ 事件 */

document.addEventListener('click', (e) => {
  const probeBtn = e.target.closest('[data-probe]');
  if (probeBtn) {
    runWebrtcProbe();
    e.stopPropagation();
    return;
  }

  const copyBtn = e.target.closest('[data-copy]');
  if (copyBtn) {
    navigator.clipboard.writeText(copyBtn.dataset.copy).then(() => toast('已复制')).catch(() => toast('复制失败'));
    e.stopPropagation();
    return;
  }

  const pickBtn = e.target.closest('[data-pick]');
  if (pickBtn) {
    togglePick(pickBtn.dataset.pick);
    e.stopPropagation();
    return;
  }

  const fixBtn = e.target.closest('[data-fix]');
  if (fixBtn) {
    selectForClean([fixBtn.dataset.fix]);
    e.stopPropagation();
    return;
  }

  const delBtn = e.target.closest('[data-del]');
  if (delBtn) {
    if (!confirm('删除该配置档及其中的会话、配置和凭据？不保留副本、不进废纸篓，无法还原。')) return;
    fetch('/api/profiles?slug=' + encodeURIComponent(delBtn.dataset.del),
      { method: 'DELETE', headers: ccHeaders() })
      .then(() => loadProfiles()).then(() => toast('已删除，不留副本'));
    return;
  }

  const row = e.target.closest('.row');
  if (row) {
    const id = row.dataset.id;
    if (state.open.has(id)) state.open.delete(id); else state.open.add(id);
    row.classList.toggle('open');
  }
});

$('#filterbar').addEventListener('click', (e) => {
  const chip = e.target.closest('.fchip');
  if (!chip) return;
  $$('.fchip').forEach((c) => c.classList.remove('on'));
  chip.classList.add('on');
  state.filter = chip.dataset.filter;
  renderFindings();
});

$('#search').addEventListener('input', (e) => {
  state.q = e.target.value.trim();
  renderFindings();
});

/* 选择条：全选 / 清空 / 去确认，三个都要用户自己按。 */
$('#pick-all').addEventListener('click', () => {
  const n = selectForClean(fixableItems().map((i) => i.id), { open: false });
  if (!n) toast('没有可自动处理的条目');
});
$('#pick-none').addEventListener('click', () => {
  state.sel.clear();
  updatePickBar();
});
$('#pick-go').addEventListener('click', () => {
  if (!state.sel.size) { toast('还没有勾选任何条目'); return; }
  openModal();
});

$('#btn-scan').addEventListener('click', async () => {
  const btn = $('#btn-scan');
  if (state.busy) return;
  state.busy = true;
  btn.disabled = true;
  btn.innerHTML = '<span class="loading-ring"></span><span>闯关中</span>';
  try {
    if (window.Tower) await Tower.autoRun();
  } catch (e) {
    toast(e.message);
  }
  state.busy = false;
  btn.disabled = false;
  btn.innerHTML = '<svg><use href="#i-refresh"/></svg><span>重新闯关</span>';
});

$('#modal-cancel').addEventListener('click', closeModal);
$('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });

$('#confirm-input').addEventListener('input', (e) => {
  $('#modal-go').disabled = e.target.value.trim().toUpperCase() !== 'CLEAN';
});

$('#modal-go').addEventListener('click', () => {
  if ($('#modal-go').dataset.mode === 'done') {
    closeModal();
    if (window.Tower) Tower.reload(true);
  } else {
    doClean();
  }
});

$('#btn-profile').addEventListener('click', createProfile);

/* ---- 咒物架：观察哨 + 遥测封缄 ---- */
let privacyState = null;
let privacyAction = null;
let privacyBusy = false;

async function refreshPrivacy() {
  if (privacyBusy) return;
  try {
    privacyState = await api('/api/privacy');
    const s = privacyState;
    $('#privacy-badge').textContent = !s.supported ? '仅 macOS' : s.settingsConfigured && s.hostsConfigured ? '设置已保存' : '尚未完整设置';
    $('#privacy-status').textContent = !s.supported ? '此入口仅支持 macOS。' :
      `关闭开关：${s.settingsConfigured ? '已写入' : '未齐全'} · hosts 规则：${s.hostsConfigured ? '已写入' : '未齐全'}。重启 Claude 后生效；实际流量尚未验证。${s.configError || ''}`;
    $('#privacy-enable').disabled = !s.supported || !!s.configError;
    $('#privacy-restore').disabled = !s.supported || !s.restoreAvailable || !!s.configError;
  } catch (e) { $('#privacy-status').textContent = e.message; }
}

function previewPrivacy(action) {
  if (!privacyState || privacyBusy) return;
  privacyAction = action;
  $('#privacy-preview-text').textContent = action === 'enable'
    ? `将记录四个字段原值并合并修改 ${privacyState.configPath}：关闭使用遥测、错误报告和反馈提交，并启用最小提示词模式（将跳过 hooks/skills/MCP/记忆与 CLAUDE.md 自动发现）；管理员授权后更新 /etc/hosts 的独立管理块。不会自动退出 Claude；请保存工作后自行重启。`
    : '将请求管理员授权移除本工具的 hosts 管理块，并恢复此前记录的三个配置字段。其他 hosts 规则和后来改成不同值的配置将保留。无需恢复整个旧文件。';
  $('#privacy-domains').textContent = privacyState.domains.join('\n');
  $('#privacy-preview').hidden = false;
}
$('#privacy-enable').addEventListener('click', () => previewPrivacy('enable'));
$('#privacy-restore').addEventListener('click', () => previewPrivacy('restore'));
$('#privacy-cancel').addEventListener('click', () => { $('#privacy-preview').hidden = true; privacyAction = null; });
$('#privacy-confirm').addEventListener('click', async () => {
  if (!privacyState || !privacyAction || privacyBusy) return;
  privacyBusy = true;
  ['privacy-enable', 'privacy-restore', 'privacy-confirm', 'privacy-cancel'].forEach(id => { $('#' + id).disabled = true; });
  $('#privacy-status').textContent = '等待 macOS 管理员授权…';
  try {
    await api('/api/privacy', { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CClean-Privacy-Token': privacyState.token },
      body: { action: privacyAction, confirm: true } });
    toast('持久设置已更新。请保存工作并重启 Claude。', 5000);
  } catch (e) { toast(e.message, 6500); }
  finally {
    privacyBusy = false;
    privacyAction = null;
    $('#privacy-preview').hidden = true;
    $('#privacy-confirm').disabled = false;
    $('#privacy-cancel').disabled = false;
    await refreshPrivacy();
  }
});

/* ---- 出口国家预期：可选，不设置就不判断 ---- */
let netcfgState = null;
let netcfgBusy = false;

async function refreshNetcfg() {
  if (netcfgBusy) return;
  try {
    netcfgState = await api('/api/netcfg');
    const s = netcfgState;
    $('#netcfg-country').value = s.country || '';
    $('#netcfg-badge').className = 'badge' + (s.country ? ' pass' : '');
    $('#netcfg-badge').textContent = s.country ? `已设 ${s.country}` : '未设置';
    $('#netcfg-status').textContent = s.error ? s.error :
      (s.country
        ? `预期出口国家：${s.country}。扫描会在实际国家不一致时给出偏高提示；不会自动改地区。`
        : '未设置预期国家：扫描不会判断出口国家。');
    $('#netcfg-save').disabled = !!s.error;
    $('#netcfg-clear').disabled = !s.country;
  } catch (e) { $('#netcfg-status').textContent = e.message; }
}

async function saveNetcfg(value) {
  if (netcfgBusy) return;
  netcfgBusy = true;
  $('#netcfg-save').disabled = true;
  $('#netcfg-clear').disabled = true;
  try {
    await api('/api/netcfg', { method: 'POST', body: { country: value } });
    toast(value ? `已记录预期出口国家 ${value.toUpperCase()}` : '已清除出口国家预期');
  } catch (e) { toast(e.message, 6000); }
  finally {
    netcfgBusy = false;
    await refreshNetcfg();
  }
}

$('#netcfg-save').addEventListener('click', () => {
  const value = ($('#netcfg-country').value || '').trim();
  if (!/^[A-Za-z]{2}$/.test(value)) return toast('请输入两位国家代码，例如 US、JP、SG');
  saveNetcfg(value);
});
$('#netcfg-clear').addEventListener('click', () => {
  $('#netcfg-country').value = '';
  saveNetcfg('');
});
$('#netcfg-country').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('#netcfg-save').click();
});

/* ---- 按出口对齐：预期国家 / 时区 / 区域格式 ---- */
let alignState = null;
let alignAction = null;
let alignBusy = false;
let alignPicked = new Set();
let alignInit = false;

function alignTargetOf(key) {
  const row = (alignState && alignState.rows || []).find((r) => r.key === key);
  return row ? row.target : '';
}

function renderAlignRows() {
  const s = alignState;
  if (!s) return;
  $('#align-rows').innerHTML = (s.rows || []).map((r) => {
    const on = alignPicked.has(r.key);
    const cls = 'align-row' + (on ? ' on' : '') + (r.needed ? '' : ' off');
    return `<label class="${cls}">
      <input type="checkbox" data-key="${esc(r.key)}" ${on ? 'checked' : ''} ${r.needed ? '' : 'disabled'}>
      <span class="al-main">
        <span class="al-top">
          <span class="al-name">${esc(r.label)}</span>
          <span class="al-delta">${esc(r.current)} → ${esc(r.target || '—')}</span>
          ${r.needsAdmin ? '<span class="al-admin">需管理员</span>' : ''}
        </span>
        ${r.note ? `<span class="al-note">${esc(r.note)}</span>` : ''}
      </span>
    </label>`;
  }).join('');
}

async function refreshAlign() {
  if (alignBusy) return;
  try {
    alignState = await api('/api/align');
    alignAction = null;
    $('#align-preview').hidden = true;
    const s = alignState;
    const rows = s.rows || [];
    const needed = rows.filter((r) => r.needed);
    // 首次只默认勾「需要改、且不需要管理员」的项——改系统时钟得用户自己点
    if (!alignInit) {
      alignPicked = new Set();
      alignInit = true;
    } else {
      alignPicked = new Set([...alignPicked].filter((k) => needed.some((r) => r.key === k)));
    }
    $('#align-badge').className = 'badge' + (s.canRestore ? ' medium'
      : needed.length ? '' : ' pass');
    $('#align-badge').textContent = !s.supported ? '仅 macOS'
      : s.error ? '记录异常'
      : s.canRestore ? '已对齐过'
      : needed.length ? `${needed.length} 项可对齐`
      : '已一致';
    renderAlignRows();
    const line = [];
    if (s.error) line.push(s.error);
    else if (!s.supported) line.push('此功能仅支持 macOS。');
    else {
      const e = s.egress || {};
      line.push(e.country ? `出口 ${e.country}${e.timezone ? ' · ' + e.timezone : ''}${e.ip ? ' · ' + e.ip : ''}`
        : '出口没探到：三样都没有目标值，先确认代理是否在跑。');
      if (s.canRestore) line.push('本工具改过这几项，可一键恢复。');
    }
    $('#align-status').textContent = line.join(' ');
    $('#align-apply').disabled = !s.canApply || alignPicked.size === 0;
    $('#align-restore').disabled = !s.canRestore;
  } catch (e) {
    $('#align-badge').className = 'badge';
    $('#align-badge').textContent = '读取失败';
    $('#align-status').textContent = e.message;
    $('#align-apply').disabled = true;
    $('#align-restore').disabled = true;
  }
}

$('#align-rows').addEventListener('change', (ev) => {
  alignAction = null;
  $('#align-preview').hidden = true;
  const box = ev.target;
  if (!box || !box.dataset || !box.dataset.key) return;
  if (box.checked) alignPicked.add(box.dataset.key);
  else alignPicked.delete(box.dataset.key);
  renderAlignRows();
  $('#align-apply').disabled = !(alignState && alignState.canApply) || alignPicked.size === 0;
});

function previewAlign(action) {
  if (!alignState || alignBusy) return;
  const s = alignState;
  alignAction = action;
  if (action === 'apply') {
    const picked = (s.rows || []).filter((r) => alignPicked.has(r.key));
    if (!picked.length) return toast('先勾选要对齐的项目');
    const needsAdmin = picked.some((r) => r.needsAdmin);
    $('#align-preview-text').textContent =
      `将按上面的顺序改这 ${picked.length} 项。改之前的每个值都会记下来，随时可以恢复。` +
      (needsAdmin ? '其中「系统时区」会弹出管理员授权窗口，取消授权只跳过那一项。' : '');
    $('#align-plan').textContent = picked.map((r) =>
      `${r.label}：${r.current} → ${r.target}`).join('\n');
    $('#align-confirm').textContent = '确认执行';
  } else {
    $('#align-preview-text').textContent =
      '将把本工具改过的项按记录写回去。时区需要管理员授权；中途失败会停下并保留记录，可以重试。';
    $('#align-plan').textContent = '恢复顺序：系统语言 → 区域格式 → 系统时区 → 预期国家（只恢复本工具改过的）';
    $('#align-confirm').textContent = '确认恢复';
  }
  $('#align-confirm').disabled = false;
  $('#align-preview').hidden = false;
}

$('#align-apply').addEventListener('click', () => previewAlign('apply'));
$('#align-restore').addEventListener('click', () => previewAlign('restore'));
$('#align-cancel').addEventListener('click', () => {
  $('#align-preview').hidden = true;
  alignAction = null;
});
$('#align-confirm').addEventListener('click', async () => {
  if (!alignState || !alignAction || alignBusy) return;
  alignBusy = true;
  ['align-apply', 'align-restore', 'align-confirm', 'align-cancel'].forEach((id) => {
    $('#' + id).disabled = true;
  });
  $('#align-status').textContent = alignAction === 'apply'
    ? '正在执行；时区那一项可能要等你在系统窗口里授权…' : '正在恢复…';
  try {
    const body = { action: alignAction, confirm: true };
    if (alignAction === 'apply') {
      body.keys = [...alignPicked];
      body.country = alignTargetOf('country');
      body.timezone = alignTargetOf('timezone');
      body.locale = alignTargetOf('locale');
      body.language = alignTargetOf('language');
    }
    const res = await api('/api/align', { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CClean-Privacy-Token': alignState.token },
      body });
    toast(res.message || '已执行。', 9000);
  } catch (e) { toast(e.message, 9000); }
  finally {
    alignBusy = false;
    alignAction = null;
    alignInit = false;
    $('#align-preview').hidden = true;
    $('#align-confirm').disabled = false;
    $('#align-cancel').disabled = false;
    await refreshAlign();
  }
});

/* ---- 区域格式：把 AppleLocale 改成跟出口一致 ---- */
let regionState = null;
let regionAction = null;
let regionBusy = false;

function regionLocaleFor(code) {
  const key = String(code || '').toUpperCase();
  const map = (regionState && regionState.locales) || {};
  return map[key] || (key ? `en_${key}` : '');
}

async function refreshRegion() {
  if (regionBusy) return;
  try {
    regionState = await api('/api/region');
    const s = regionState;
    const same = s.region && s.savedRegion && s.region === s.savedRegion;
    $('#region-badge').className = 'badge' + (s.canRestore ? (same ? ' pass' : ' medium')
      : s.region ? ' pass' : '');
    $('#region-badge').textContent = !s.supported ? '仅 macOS'
      : s.error ? '记录异常'
      : s.canRestore ? (same ? '已改成目标' : '已改过')
      : s.region ? s.region : '读不到';
    const line = [];
    if (s.error) line.push(s.error);
    else if (!s.supported) line.push('此功能仅支持 macOS。');
    else {
      line.push(`当前：${s.locale || '读不到'}${s.region ? `（地区 ${s.region}）` : ''}`);
      if (s.canRestore) line.push(`本工具改过，原值是 ${s.previous}，可恢复。`);
      else line.push('没有被本工具改过。');
    }
    $('#region-status').textContent = line.join(' ');
    $('#region-apply').disabled = !s.supported || !!s.error || !!s.canRestore;
    $('#region-restore').disabled = !s.canRestore;
  } catch (e) {
    $('#region-badge').className = 'badge';
    $('#region-badge').textContent = '读取失败';
    $('#region-status').textContent = e.message;
    $('#region-apply').disabled = true;
    $('#region-restore').disabled = true;
  }
}

function previewRegion(action) {
  if (!regionState || regionBusy) return;
  const s = regionState;
  regionAction = action;
  if (action === 'apply') {
    const code = ($('#region-target').value || '').trim().toUpperCase();
    if (!/^[A-Za-z]{2}$/.test(code)) return toast('请输入两位国家代码，例如 US、JP、SG');
    const locale = regionLocaleFor(code);
    $('#region-preview-text').textContent =
      `将把 AppleLocale 从 ${s.locale || '（读不到）'} 改成 ${locale}（地区 ${code}）。` +
      '只改这一个键，不动系统语言和时区；重启浏览器或重新登录后生效。' +
      '改之前的值会记下来，随时可以恢复。';
    $('#region-confirm').textContent = `确认改成 ${locale}`;
  } else {
    $('#region-preview-text').textContent =
      `将把 AppleLocale 恢复为 ${s.previous}（本工具改之前的值）。恢复后记录会删除。`;
    $('#region-confirm').textContent = '确认恢复';
  }
  $('#region-confirm').disabled = false;
  $('#region-preview').hidden = false;
}

$('#region-apply').addEventListener('click', () => previewRegion('apply'));
$('#region-restore').addEventListener('click', () => previewRegion('restore'));
$('#region-cancel').addEventListener('click', () => {
  $('#region-preview').hidden = true;
  regionAction = null;
});
$('#region-target').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('#region-apply').click();
});
$('#region-confirm').addEventListener('click', async () => {
  if (!regionState || !regionAction || regionBusy) return;
  regionBusy = true;
  ['region-apply', 'region-restore', 'region-confirm', 'region-cancel'].forEach((id) => {
    $('#' + id).disabled = true;
  });
  try {
    const body = { action: regionAction, confirm: true };
    if (regionAction === 'apply') {
      const code = ($('#region-target').value || '').trim().toUpperCase();
      body.region = code;
      body.locale = regionLocaleFor(code);
    }
    const res = await api('/api/region', { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CClean-Privacy-Token': regionState.token },
      body });
    toast(res.message || '区域格式已更新。', 8000);
  } catch (e) { toast(e.message, 8000); }
  finally {
    regionBusy = false;
    regionAction = null;
    $('#region-preview').hidden = true;
    $('#region-confirm').disabled = false;
    $('#region-cancel').disabled = false;
    await refreshRegion();
  }
});

/* ---- IPv6 出口：系统级关闭 / 恢复 ---- */
let ipv6State = null;
let ipv6Action = null;
let ipv6Busy = false;

function ipv6ModeLabel(mode) {
  const m = String(mode || '').toLowerCase();
  if (m === 'automatic') return 'Automatic';
  if (m === 'off') return 'Off';
  if (m.includes('link')) return '仅本地链路';
  if (m.includes('manual')) return '手动';
  return mode || '未知';
}

async function refreshIPv6() {
  if (ipv6Busy) return;
  try {
    ipv6State = await api('/api/ipv6');
    const s = ipv6State;
    if (!s.supported) {
      $('#ipv6-badge').className = 'badge';
      $('#ipv6-badge').textContent = '仅 macOS';
      $('#ipv6-status').textContent = '此入口仅支持 macOS。';
      $('#ipv6-off').disabled = true;
      $('#ipv6-restore').disabled = true;
      return;
    }
    const auto = s.automatic || [];
    const off = s.disabled || [];
    const ex = s.exposure || {};
    $('#ipv6-badge').className = 'badge' + (s.applied ? ' pass' : auto.length ? ' medium' : '');
    $('#ipv6-badge').textContent = s.applied ? 'Wi-Fi 已关闭'
      : s.stateError ? '记录异常'
      : s.readError ? '读取失败'
      : s.wifiError ? '没有 Wi-Fi'
      : auto.length ? '未关闭'
      : off.length ? 'Wi-Fi 已 Off' : '无可改服务';
    const line = [
      s.wifi ? `${s.wifi} 当前 IPv6：${ipv6ModeLabel(s.wifiMode)}。` : (s.wifiError || '没有已启用的 Wi-Fi 网络服务。'),
      `只改 Wi-Fi，其它 ${Math.max(0, (s.services || []).length - 1)} 个已启用网络服务不在关闭范围内。`,
      `系统当前${ex.has_global_v6 ? '有' : '没有'}全局 IPv6 地址${ex.has_default_v6_route ? '，且有 v6 默认路由' : ''}。`,
    ];
    if (s.applied) line.push(`本工具已关闭：${s.changed.join('、')}。可随时恢复为 Automatic。`);
    if (s.readError) line.push(s.readError);
    if (s.stateError) line.push(`${s.stateError}（记录：${s.statePath}）`);
    else if (s.restoreAvailable && !s.applied) line.push('有恢复记录，但当前没有服务处于 Off；点「恢复为 Automatic」可清理记录。');
    $('#ipv6-status').textContent = line.join(' ');
    $('#ipv6-off').disabled = !auto.length || !!s.stateError || !!s.readError || !!s.wifiError;
    $('#ipv6-restore').disabled = !s.restoreAvailable || !!s.readError;
  } catch (e) {
    $('#ipv6-badge').className = 'badge';
    $('#ipv6-badge').textContent = '读取失败';
    $('#ipv6-status').textContent = e.message;
    $('#ipv6-off').disabled = true;
    $('#ipv6-restore').disabled = true;
  }
}

function previewIPv6(action) {
  if (!ipv6State || ipv6Busy) return;
  ipv6Action = action;
  const s = ipv6State;
  const pre = $('#ipv6-services');
  if (action === 'off') {
    const rows = (s.services || []).filter((r) => /^automatic$/i.test(r.mode || ''));
    $('#ipv6-preview-text').textContent =
      `将请求 macOS 管理员授权，只对 Wi-Fi 执行「关闭 IPv6」（networksetup -setv6off），共 ${rows.length} 个服务。` +
      '以太网、VPN、USB 网络等其它服务不动；不会改代理软件内的 ipv6 开关，也不验证代理远端解析；IPv6-only 热点会断，依赖 v6 的应用可能受限。';
    pre.textContent = rows.map((r) => `${r.name}  ${ipv6ModeLabel(r.mode)} → Off`).join('\n');
    $('#ipv6-ack-wrap').hidden = false;
    $('#ipv6-ack').checked = false;
    $('#ipv6-confirm').disabled = true;
    $('#ipv6-confirm').textContent = '确认关闭 Wi-Fi 并请求管理员授权';
  } else {
    const rows = (s.services || []).filter((r) => (s.changed || []).includes(r.name));
    const empty = rows.length === 0;
    $('#ipv6-preview-text').textContent = empty
      ? '没有需要恢复的服务；确认后会删除本工具的恢复记录，不会请求管理员权限。'
      : '将请求 macOS 管理员授权，把本工具关闭过的服务恢复为 Automatic。' +
        '已被你手动改成其他值的服务不会覆盖；IPv6 会重新可用。';
    pre.textContent = empty ? '（无）'
      : rows.map((r) => `${r.name}  ${ipv6ModeLabel(r.mode)} → Automatic`).join('\n');
    $('#ipv6-ack-wrap').hidden = true;
    $('#ipv6-confirm').disabled = false;
    $('#ipv6-confirm').textContent = empty ? '清理恢复记录' : '确认恢复并请求管理员授权';
  }
  $('#ipv6-preview').hidden = false;
}

$('#ipv6-off').addEventListener('click', () => previewIPv6('off'));
$('#ipv6-restore').addEventListener('click', () => previewIPv6('restore'));
$('#ipv6-cancel').addEventListener('click', () => { $('#ipv6-preview').hidden = true; ipv6Action = null; });
$('#ipv6-ack').addEventListener('change', () => {
  if (ipv6Action === 'off') $('#ipv6-confirm').disabled = !$('#ipv6-ack').checked;
});
$('#ipv6-confirm').addEventListener('click', async () => {
  if (!ipv6State || !ipv6Action || ipv6Busy) return;
  if (ipv6Action === 'off' && !$('#ipv6-ack').checked) return;
  ipv6Busy = true;
  ['ipv6-off', 'ipv6-restore', 'ipv6-confirm', 'ipv6-cancel'].forEach((id) => { $('#' + id).disabled = true; });
  $('#ipv6-status').textContent = '等待 macOS 管理员授权…';
  try {
    const res = await api('/api/ipv6', { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CClean-Privacy-Token': ipv6State.token },
      body: { action: ipv6Action, confirm: true } });
    toast(res.message || 'IPv6 设置已更新。', 6000);
  } catch (e) { toast(e.message, 7000); }
  finally {
    ipv6Busy = false;
    ipv6Action = null;
    $('#ipv6-preview').hidden = true;
    $('#ipv6-confirm').disabled = false;
    $('#ipv6-cancel').disabled = false;
    await refreshIPv6();
  }
});

/* ---- 分流规则：FlClash 全局附加规则写入 / 撤销 ---- */
let proxyfixState = null;
let proxyfixAction = null;
let proxyfixBusy = false;
let proxyfixPortMode = 'proxy';

async function refreshProxyfix() {
  if (proxyfixBusy) return;
  try {
    proxyfixState = await api('/api/proxyfix?port=' + encodeURIComponent(proxyfixPortMode));
    const s = proxyfixState;
    const bad = !s.supported || !s.available;
    $('#proxyfix-badge').className = 'badge' + (s.applied ? ' pass'
      : s.manual ? ' medium'
      : s.blocked && s.blocked.length ? ' medium' : '');
    $('#proxyfix-badge').textContent = !s.supported ? '仅 macOS'
      : s.manual ? '需手动'
      : !s.available ? '不可用'
      : s.applied ? '已写入'
      : s.stateError ? '记录异常'
      : s.blocked && s.blocked.length ? '规则冲突'
      : (s.missing || []).length ? '缺规则'
      : '规则齐全';
    // 已经写下去的那一次以记录为准：界面上不允许再改，改了也对不上。
    const portSel = $('#proxyfix-port');
    portSel.value = s.applied ? (s.portMode || 'proxy') : proxyfixPortMode;
    portSel.disabled = !!s.applied || !!s.manual || !s.supported;
    const guidance = (s.guidance || []).join('\n');
    $('#proxyfix-guidance').hidden = !s.manual || !guidance;
    $('#proxyfix-guidance').textContent = guidance;
    if (bad) {
      const head = s.client ? `客户端：${s.client}（${s.running ? '运行中' : '未运行'}）。` : '';
      $('#proxyfix-status').textContent = head + (s.reason || '当前无法使用。');
    } else {
      const line = [
        `客户端：${s.client}（${s.running ? '运行中' : '未运行'}）`,
        `分流策略：${s.policy || '未识别'}`,
        `端口：${s.portMode === 'reject' ? '直接拒绝' : '跟着代理组走'}`,
        `已覆盖 ${(s.covered || []).length}/${(s.rules || []).length} 条。`,
      ];
      if (s.applied) line.push(`本工具已写入 ${s.savedCount || 0} 条附加规则，可随时撤销。`);
      if (s.blocked && s.blocked.length) line.push(`冲突：${s.blocked.join('；')}。`);
      if (s.reason && !s.applied) line.push(s.reason + '。');
      if (s.stateError) line.push(s.stateError);
      $('#proxyfix-status').textContent = line.join(' ');
    }
    $('#proxyfix-apply').disabled = !s.canApply;
    $('#proxyfix-undo').disabled = !s.canUndo;
  } catch (e) {
    $('#proxyfix-badge').className = 'badge';
    $('#proxyfix-badge').textContent = '读取失败';
    $('#proxyfix-status').textContent = e.message;
    $('#proxyfix-apply').disabled = true;
    $('#proxyfix-undo').disabled = true;
  }
}

$('#proxyfix-port').addEventListener('change', () => {
  proxyfixPortMode = $('#proxyfix-port').value === 'reject' ? 'reject' : 'proxy';
  // 预览是按旧策略算出来的，策略一变就得重新来
  $('#proxyfix-preview').hidden = true;
  proxyfixAction = null;
  refreshProxyfix();
});

function previewProxyfix(action) {
  if (!proxyfixState || proxyfixBusy) return;
  proxyfixAction = action;
  const s = proxyfixState;
  if (action === 'apply') {
    const rules = s.missing || [];
    const portText = s.portMode === 'reject'
      ? 'STUN/TURN 端口写成 REJECT，UDP 出不去'
      : `STUN/TURN 端口跟着 ${s.policy} 走`;
    $('#proxyfix-preview-text').textContent =
      `将向 ${s.client} 的全局附加规则写入 ${rules.length} 条（域名走 ${s.policy}；${portText}），` +
      '排到现有附加规则之前；订阅里的其它规则不动。' +
      `写入后退出并重开 ${s.client}，代理中断几秒。`;
    $('#proxyfix-rules').textContent = rules.join('\n');
    $('#proxyfix-confirm').textContent = `确认写入并重启 ${s.client}`;
  } else {
    const rules = s.savedRules || [];
    $('#proxyfix-preview-text').textContent =
      `将删除本工具记录的 ${s.savedCount || 0} 条附加规则，并移除运行配置里的标记块` +
      `${s.running ? `，然后退出并重开 ${s.client}` : ''}。` +
      '你后来手动改过的行会让撤销整体中止，不会覆盖你的修改。';
    $('#proxyfix-rules').textContent = rules.length ? rules.join('\n') : '（记录里没有规则文本）';
    $('#proxyfix-confirm').textContent = s.running ? `确认撤销并重启 ${s.client}` : '确认撤销';
  }
  $('#proxyfix-confirm').disabled = false;
  $('#proxyfix-preview').hidden = false;
}

$('#proxyfix-apply').addEventListener('click', () => previewProxyfix('apply'));
$('#proxyfix-undo').addEventListener('click', () => previewProxyfix('undo'));
$('#proxyfix-cancel').addEventListener('click', () => { $('#proxyfix-preview').hidden = true; proxyfixAction = null; });
$('#proxyfix-confirm').addEventListener('click', async () => {
  if (!proxyfixState || !proxyfixAction || proxyfixBusy) return;
  proxyfixBusy = true;
  ['proxyfix-apply', 'proxyfix-undo', 'proxyfix-confirm', 'proxyfix-cancel'].forEach((id) => { $('#' + id).disabled = true; });
  $('#proxyfix-status').textContent =
    `正在退出并重开 ${proxyfixState.client || '代理客户端'}，请稍候…`;
  try {
    const res = await api('/api/proxyfix', { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CClean-Privacy-Token': proxyfixState.token },
      body: { action: proxyfixAction, confirm: true, portMode: proxyfixPortMode } });
    toast(res.message || '分流规则已更新。', 8000);
  } catch (e) { toast(e.message, 8000); }
  finally {
    proxyfixBusy = false;
    proxyfixAction = null;
    $('#proxyfix-preview').hidden = true;
    $('#proxyfix-confirm').disabled = false;
    $('#proxyfix-cancel').disabled = false;
    await refreshProxyfix();
  }
});

/* ---- 自动更新：检查 → 下载校验 → 用户确认后安装 ---- */
let updateState = null;
let updateBusy = false;
let updatePoll = null;
let installArmed = 0;

function updateBadge(text, tone) {
  const b = $('#update-badge');
  b.className = 'badge' + (tone ? ' ' + tone : '');
  b.textContent = text;
}

function updateTime(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function disarmInstall() {
  if (!installArmed) return;
  installArmed = 0;
  if (updateState) renderUpdate(updateState);
}

function renderUpdate(s) {
  if (!s || !s.ok) return;
  updateState = s;
  const repo = $('#update-repo');
  if (document.activeElement !== repo) repo.value = s.repo || '';
  $('#update-auto').checked = !!s.autoCheck;

  const latest = s.latest || null;
  const actions = $('#update-actions');
  const install = $('#update-install');
  const discard = $('#update-discard');
  $('#update-install-note').hidden = true;
  $('#update-notes').hidden = !(latest && latest.notes);
  if (latest && latest.notes) $('#update-notes').textContent = latest.notes;

  if (!s.configured) {
    updateBadge('未配置', 'info');
    $('#update-status').textContent = '还没有填写更新源，自动更新完全关闭（不联网）。';
    $('#update-latest').hidden = true;
    actions.hidden = true;
    return;
  }
  if (s.installing) {
    updateBadge('安装中', 'medium');
    $('#update-status').textContent = '正在替换应用并重启，页面会自动断开。';
    $('#update-latest').hidden = true;
    actions.hidden = true;
    return;
  }

  if (s.newer) updateBadge(s.stagedReady ? '待安装' : '有新版本', 'medium');
  else if (s.lastError && !latest) updateBadge('检查失败', 'critical');
  else if (s.lastCheck) updateBadge('已是最新', 'pass');
  else updateBadge('待检查', 'info');

  if (latest) {
    $('#update-latest').hidden = false;
    $('#update-latest').textContent =
      `最新 ${latest.version} · 哨兵 ${latest.shieldVersion}` +
      (latest.minMacOS ? ` · 最低 macOS ${latest.minMacOS}` : '');
  } else {
    $('#update-latest').hidden = true;
  }

  const lines = [];
  if (s.stagedReady) lines.push('新版已下载：体积、SHA256、版本号与代码签名全部通过。');
  if (s.lastCheck) lines.push(`上次检查 ${updateTime(s.lastCheck)}`);
  if (s.phase === 'check') lines.push('正在检查…');
  if (s.phase === 'download') lines.push('正在下载并校验…');
  if (s.lastError) lines.push(`上次出错：${s.lastError}`);
  const li = s.lastInstall;
  if (li && li.at) {
    lines.push(li.ok
      ? `上次更新 ${li.from} → ${li.to} 成功（${updateTime(li.at)}）`
      : `上次更新 ${li.from} → ${li.to} 失败：${li.reasonText || '已回滚'}（${updateTime(li.at)}）`);
  }
  $('#update-status').textContent = lines.join('\n') || '还没有检查过。';

  actions.hidden = !(s.newer || s.stagedReady);
  install.disabled = updateBusy;
  discard.disabled = updateBusy;
  if (s.stagedReady) {
    install.textContent = installArmed ? '确认安装（重启塔与哨兵）' : '安装并重启';
    discard.hidden = false;
    $('#update-install-note').hidden = false;
    $('#update-install-note').textContent =
      `已下载 ${latest ? latest.version : ''}。安装会先退出塔与哨兵，把旧版备份到 ~/.ccclean/update-backup 再换新；新包起不来或校验不过会自动回滚。`;
  } else {
    install.textContent = '下载新版';
    discard.hidden = true;
  }
}

async function refreshUpdate(silent) {
  if (silent && updateBusy) return;
  try {
    const s = await api('/api/update');
    renderUpdate(s);
    if (s.requested) {
      if (!$('#panel-privacy').classList.contains('active')) switchTab('privacy');
      const card = $('#update-card');
      card.scrollIntoView({ behavior: 'smooth', block: 'center' });
      card.classList.remove('focus-flash');
      setTimeout(() => card.classList.add('focus-flash'), 30);
      setTimeout(() => card.classList.remove('focus-flash'), 2200);
    }
  } catch (e) {
    if (!silent) {
      updateBadge('读取失败', 'critical');
      $('#update-status').textContent = e.message;
    }
  }
}

function startUpdatePoll() {
  if (updatePoll) return;
  // 后台下载与安装都要靠轮询拿状态。8 秒一次只读本地文件，
  // 联网检查由服务端按 checkHours 自己节流。
  updatePoll = setInterval(() => {
    if (document.visibilityState === 'visible') refreshUpdate(true);
  }, 8000);
}

async function saveUpdateRepo() {
  if (updateBusy) return;
  updateBusy = true;
  $('#update-save').disabled = true;
  $('#update-status').textContent = '正在保存并检查…';
  try {
    await api('/api/update', { method: 'POST', body: {
      action: 'configure',
      repo: ($('#update-repo').value || '').trim(),
      autoCheck: $('#update-auto').checked,
    } });
    const s = await api('/api/update', { method: 'POST', body: { action: 'check' } });
    renderUpdate(s);
    toast(s.configured ? (s.newer ? '发现新版，准备下载' : '检查完成') : '已关闭自动更新', 5000);
  } catch (e) {
    toast(e.message, 8000);
    await refreshUpdate(true);
  } finally {
    updateBusy = false;
    $('#update-save').disabled = false;
  }
}

async function startUpdateDownload() {
  if (updateBusy) return;
  updateBusy = true;
  $('#update-install').disabled = true;
  try {
    const s = await api('/api/update', { method: 'POST', body: { action: 'download' } });
    renderUpdate(s);
    if (!s.started) toast('下载已经在进行', 4000);
    else toast('开始下载并校验新版', 4000);
  } catch (e) {
    toast(e.message, 8000);
  } finally {
    updateBusy = false;
    await refreshUpdate(true);
  }
}

$('#update-save').addEventListener('click', saveUpdateRepo);
$('#update-check').addEventListener('click', saveUpdateRepo);
$('#update-install').addEventListener('click', async () => {
  if (updateBusy || !updateState) return;
  if (!updateState.stagedReady) { await startUpdateDownload(); return; }
  if (!installArmed) {
    // 第一次点击只进入待确认，8 秒内没有第二次就撤回
    installArmed = 1;
    renderUpdate(updateState);
    setTimeout(disarmInstall, 8000);
    return;
  }
  installArmed = 0;
  updateBusy = true;
  $('#update-install').disabled = true;
  $('#update-discard').disabled = true;
  $('#update-status').textContent = '正在安装：塔与哨兵即将退出并重启，页面会断开。';
  try {
    await api('/api/update', { method: 'POST', body: { action: 'install', confirm: true } });
    toast('安装已开始，塔会自动重启', 8000);
  } catch (e) {
    toast(e.message, 8000);
    updateBusy = false;
    await refreshUpdate(true);
  }
});
$('#update-discard').addEventListener('click', async () => {
  if (updateBusy) return;
  updateBusy = true;
  try {
    await api('/api/update', { method: 'POST', body: { action: 'discard' } });
    toast('已丢弃暂存的安装包', 4000);
  } catch (e) {
    toast(e.message, 6000);
  } finally {
    updateBusy = false;
    await refreshUpdate(true);
  }
});

/* ---- 卸载器：把本工具自己留下的东西清干净 ---- */
let uninstallPlan = null;
let uninstallBusy = false;

async function loadUninstall() {
  if (uninstallBusy) return;
  try {
    uninstallPlan = await api('/api/uninstall');
  } catch (e) {
    $('#uninstall-badge').textContent = '读取失败';
    $('#uninstall-total').textContent = e.message;
    return;
  }
  const p = uninstallPlan;
  const usable = p.items.filter((i) => i.available);
  const picked = p.items.filter((i) => i.available && i.default);
  $('#uninstall-badge').textContent = usable.length ? `${usable.length} 项可处理` : '没有可处理的项';
  $('#uninstall-list').innerHTML = p.items.map((it) => `
    <label class="un-item${it.available ? '' : ' off'}">
      <input type="checkbox" data-un="${esc(it.id)}"${it.available && it.default ? ' checked' : ''}${it.available ? '' : ' disabled'}>
      <span class="un-main">
        <span class="un-title">${esc(it.title)}<i class="un-size">${esc(it.sizeText)}</i></span>
        <span class="un-path mono">${esc((it.paths || []).join(' · ') || '—')}</span>
        <span class="un-why">${esc(it.why)}</span>
        <span class="un-danger">${esc(it.danger)}</span>
      </span>
    </label>`).join('');
  // 不预填确认串：让「确认」这件事真的花一点力气，和清理那一关一个道理
  $('#uninstall-confirm').value = '';
  $('#uninstall-confirm').disabled = false;
  $('#uninstall-go').disabled = true;
  $('#uninstall-total').textContent =
    `合计 ${p.totalText}；默认勾选 ${picked.length} 项。` + (p.warnings || []).join(' ');
}

async function doUninstall() {
  if (!uninstallPlan || uninstallBusy) return;
  const ids = $$('#uninstall-list input[data-un]')
    .filter((el) => el.checked && !el.disabled)
    .map((el) => el.dataset.un);
  if (!ids.length) { toast('没有勾选任何项目'); return; }
  const word = ($('#uninstall-confirm').value || '').trim().toUpperCase();
  if (word !== uninstallPlan.confirmWord) { toast('请输入 UNINSTALL 确认'); return; }

  uninstallBusy = true;
  $('#uninstall-go').disabled = true;
  $('#uninstall-result').hidden = false;
  $('#uninstall-result').textContent = `正在处理 ${ids.length} 项，请稍候…`;
  try {
    const r = await api('/api/uninstall', { method: 'POST', body: { ids, confirm: word } });
    const lines = r.results.map((x) => `${x.ok ? '✓' : '✗'} ${x.title}：${x.message}`);
    lines.push('');
    lines.push('复查：');
    lines.push(...((r.left || []).length ? r.left.map((x) => '· ' + x) : ['· 没有发现残留。']));
    if (r.quit) lines.push('', '应用包已移除，本程序即将退出。');
    $('#uninstall-result').textContent = lines.join('\n');
    toast(r.quit ? '卸载完成，程序即将退出' : '卸载完成', 6000);
    if (!r.quit) { uninstallBusy = false; await loadUninstall(); }
  } catch (e) {
    $('#uninstall-result').textContent = '执行失败：' + e.message;
    toast(e.message, 6000);
    uninstallBusy = false;
    $('#uninstall-go').disabled = false;
  }
}

$('#uninstall-confirm').addEventListener('input', (e) => {
  const want = (uninstallPlan && uninstallPlan.confirmWord) || 'UNINSTALL';
  $('#uninstall-go').disabled = e.target.value.trim().toUpperCase() !== want;
});
$('#uninstall-go').addEventListener('click', doUninstall);
$('#uninstall-reload').addEventListener('click', () => { loadUninstall(); });

let watchOn = false;

async function refreshWatch() {
  try {
    const s = await api('/api/watch');
    watchOn = !!s.running;
    $('#watch-badge').textContent = s.running ? '放哨中' : '未上线';
    $('#watch-badge').classList.toggle('on', !!s.running);
    $('#watch-toggle').textContent = s.running ? '收哨' : '放哨';
    $('#watch-addr').textContent = s.running ? `代理地址 127.0.0.1:${s.port}` : '';
    $('#watch-log').textContent = (s.log || []).join('\n');
    const log = $('#watch-log');
    log.scrollTop = log.scrollHeight;
  } catch (_) { /* 服务不可用就跳过 */ }
}

$('#watch-toggle').addEventListener('click', async () => {
  try {
    await api(watchOn ? '/api/watch/stop' : '/api/watch/start', { method: 'POST', body: {} });
    toast(watchOn ? '观察哨已收哨' : '观察哨已放哨', 2400);
  } catch (e) {
    toast(e.message);
  }
  refreshWatch();
});

$('#hosts-block-gen').addEventListener('click', async () => {
  try {
    const r = await api('/api/tool/hosts-block');
    toast('已生成 ' + r.path, 4200);
  } catch (e) {
    toast(e.message);
  }
});

/* ---- 咒物架：出口足迹 ---- */

async function loadEgress() {
  const box = $('#egress-list');
  if (!box) return;
  try {
    renderEgress(await api('/api/egress?limit=40'));
  } catch (e) {
    box.innerHTML = `<div class="egress-empty">读取失败：${esc(e.message)}</div>`;
  }
}

function renderEgress(d) {
  const box = $('#egress-list');
  const badge = $('#egress-badge');
  const sum = $('#egress-sum');
  const dr = d.drift || {};
  const chrono = d.history || [];

  if (!chrono.length) {
    badge.textContent = '无记录';
    badge.className = 'badge';
    sum.textContent = '还没记录过出口';
    box.innerHTML = '<div class="egress-empty">还没有出口记录。跑一次检测就会记下当时的 IP、国家与 ASN；多跑几天，才看得出有没有漂移。</div>';
    return;
  }

  const countries = dr.countries || [];
  const asns = dr.asns || [];
  const risky = countries.length >= 3 || asns.length >= 3;
  if (!dr.enough) {
    badge.textContent = '记录不足';
    badge.className = 'badge';
  } else {
    badge.textContent = `${countries.length} 国 · 跳变 ${dr.switches} 次`;
    badge.className = 'badge ' + (risky || countries.length >= 2 ? 'warn' : 'ok');
  }
  sum.textContent = `24h 内 ${dr.count || 0} 条 · 累计 ${dr.total || chrono.length} 条 · 跨度 ${dr.spanHours || 0}h`;

  // 相邻两条国家不同 = 一次跳变，标出来（按时间正序算，倒序显示）
  const shift = chrono.map((r, i) => i > 0 && (r.country || '') !== (chrono[i - 1].country || ''));
  box.innerHTML = chrono
    .map((r, i) => ({ ...r, shift: shift[i] }))
    .reverse()
    .map((r) => `<div class="egress-row${r.shift ? ' shift' : ''}" title="${esc(r.ip)}${r.org ? ' · ' + esc(r.org) : ''}">
        <span class="t">${esc(r.at)}</span>
        <span class="geo">${esc(r.country || '??')}${r.city ? `<em>${esc(r.city)}</em>` : ''}</span>
        <span class="asn">${r.asn ? 'AS' + esc(r.asn) : '—'}</span>
      </div>`)
    .join('');
}

$('#egress-refresh')?.addEventListener('click', () => {
  $('#egress-sum').textContent = '读取中…';
  loadEgress();
});

/* ---- 咒物架：全量快照 ---- */

$('#snapshot-make')?.addEventListener('click', async (e) => {
  const btn = e.target;
  btn.disabled = true;
  $('#snapshot-status').textContent = '排除缓存、日志和凭据后保存…';
  try {
    const r = await api('/api/snapshot', { method: 'POST', body: {} });
    $('#snapshot-status').textContent = r.message;
    toast('快照已拍好', 2400);
  } catch (err) {
    $('#snapshot-status').textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

/* ---- 咒物架：备份与还原 ---- */

const KIND_LABEL = {
  json_keys: '配置字段', json_patch: '配置补丁', shellrc: '启动脚本',
  rotate_ids: '机器标识', trash: '移入废纸篓', keychain: '钥匙串', envvar: '环境变量',
  startup: '登录项',
  no_copy: '不留副本',
};
// 这几类没有原始值可还原，界面上先说清楚，别让人以为点了就全能回去
const KIND_NO_RESTORE = new Set(['keychain', 'envvar', 'startup', 'no_copy']);

async function loadBackups() {
  const box = $('#restore-list');
  if (!box) return;
  try {
    renderBackups(await api('/api/backups'));
  } catch (e) {
    box.innerHTML = `<div class="egress-empty">读取失败：${esc(e.message)}</div>`;
  }
}

function renderBackups(d) {
  const box = $('#restore-list');
  const badge = $('#restore-badge');
  const sum = $('#restore-sum');
  const list = d.backups || [];
  if (!list.length) {
    badge.textContent = '无备份';
    badge.className = 'badge';
    sum.textContent = '还没执行过清理';
    box.innerHTML = '<div class="egress-empty">还没有清理记录。执行清理后会列出操作清单；不留副本的项目不可还原。</div>';
    return;
  }
  badge.textContent = `${list.length} 次记录`;
  badge.className = 'badge';
  const newest = list[0];
  sum.textContent = `最近一次 ${newest.createdAt || newest.id}`;

  box.innerHTML = list.map((b) => {
    const kinds = Object.entries(b.kinds || {})
      .map(([k, n]) => `${KIND_LABEL[k] || k}×${n}`).join(' · ') || '空清单';
    const lost = Object.keys(b.kinds || {}).filter((k) => KIND_NO_RESTORE.has(k));
    return `<div class="egress-row" style="grid-template-columns:1fr auto;align-items:center;gap:10px">
        <span>
          <span class="t">${esc(b.createdAt || b.id)}</span>
          <span class="geo"><em>${esc(kinds)}</em></span>
          ${lost.length ? `<span class="asn" title="这一类没有原始值可还原">${esc(lost.map((k) => KIND_LABEL[k] || k).join('、'))} 不可还原</span>` : ''}
        </span>
        <button class="btn sm" data-restore="${esc(b.id)}"${b.restorable ? '' : ' disabled'}>还原</button>
      </div>`;
  }).join('');
}

let restoreArmed = '';
$('#restore-refresh')?.addEventListener('click', () => {
  $('#restore-sum').textContent = '读取中…';
  loadBackups();
});

$('#restore-list')?.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-restore]');
  if (!btn || btn.disabled) return;
  const id = btn.dataset.restore;
  // 还原会覆盖现有文件，跟「改时区」一样要两步确认
  if (restoreArmed !== id) {
    restoreArmed = id;
    btn.textContent = '再点一次确认';
    setTimeout(() => {
      if (restoreArmed === id) { restoreArmed = ''; btn.textContent = '还原'; }
    }, 5000);
    return;
  }
  restoreArmed = '';
  btn.disabled = true;
  btn.textContent = '还原中…';
  try {
    const r = await api('/api/backups/restore', { method: 'POST', body: { id, confirm: 'RESTORE' } });
    const res = r.result || {};
    const skipped = res.skipped || [];
    $('#restore-sum').textContent = res.message || '已还原';
    toast(res.ok ? (res.message || '已还原') : '没有可还原的内容', 3600);
    if (skipped.length) {
      const box = $('#restore-list');
      box.insertAdjacentHTML('afterbegin',
        `<div class="egress-empty" style="line-height:1.7">
          <strong>需手动处理（${skipped.length} 项）</strong><br>
          ${skipped.map((s) => `${esc(s.id)}：${esc(s.reason)}`).join('<br>')}
        </div>`);
    }
    if (r.backups) renderBackups({ backups: r.backups });
  } catch (err) {
    btn.disabled = false;
    btn.textContent = '还原';
    $('#restore-sum').textContent = err.message;
    toast(err.message, 3600);
  }
});

/* ---- 咒物架：系统时区 ---- */

let tzArmed = false;
async function loadTz() {
  const el = $('#tz-status');
  if (!el) return;
  try {
    const r = await api('/api/timezone');
    el.textContent = `当前 ${r.tz || '未知'}`;
    $('#tz-apply').disabled = !r.supported;
  } catch (_) {
    el.textContent = '读取失败';
  }
}

$('#tz-apply')?.addEventListener('click', async (e) => {
  const btn = e.target;
  const tz = $('#tz-select').value;
  if (!tzArmed) {
    tzArmed = true;
    btn.textContent = `再点一次确认改为 ${tz}`;
    setTimeout(() => { tzArmed = false; btn.textContent = '授权修改'; }, 5000);
    return;
  }
  tzArmed = false;
  btn.disabled = true;
  btn.textContent = '授权修改';
  $('#tz-status').textContent = '等待系统授权…';
  try {
    const r = await api('/api/timezone', { method: 'POST', body: { tz, confirm: true } });
    $('#tz-status').textContent = r.ok ? `已改为 ${r.tz}` : `未完成：${r.message}`;
    toast(r.ok ? '时区已生效' : r.message, 3000);
  } catch (err) {
    $('#tz-status').textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

$('#checklist').addEventListener('click', (e) => {
  const item = e.target.closest('.ck-item');
  if (!item) return;
  e.preventDefault();
  const id = item.dataset.id;
  if (ckDone.has(id)) ckDone.delete(id); else ckDone.add(id);
  item.classList.toggle('done');
  updateCk();
  syncChecklist();
});

function switchTab(name) {
  if (GATED_TABS.has(name) && state.unlocked === false) {
    toast('先下塔闯过至少一关，这片区域才会开放');
    name = 'tower';
  }
  $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  $$('.panel').forEach((p) => p.classList.toggle('active', p.id === 'panel-' + name));
  if (history.replaceState) history.replaceState(null, '', '#' + name);
  window.scrollTo({ top: 0, behavior: 'smooth' });
  if (name === 'privacy') { refreshPrivacy(); refreshNetcfg(); refreshAlign(); refreshRegion(); refreshIPv6(); refreshProxyfix(); loadUninstall(); refreshUpdate(); }
  if (name === 'isolation') loadProfiles();
  if (name === 'findings') { loadEgress(); loadBackups(); loadTz(); }
  if (name === 'tower' && window.Tower) Tower.refresh();
  if (name === 'board' && window.Tower) Tower.refreshBoard();
  if (name === 'settle' && window.Tower) Tower.refreshSettle();
  if (name === 'cruise' && window.Tower) Tower.refreshCruise();
}

$$('.tab').forEach((t) => t.addEventListener('click', () => switchTab(t.dataset.tab)));

$('#brand').addEventListener('click', () => {
  if (window.Tower && Tower.showTitle) Tower.showTitle();
});

/* ============================================================ 启动 */

(async function init() {
  try {
    const meta = await api('/api/meta');
    state.home = meta.home || '';
    const disc = $('#disclaimer');
    if (disc) disc.textContent = meta.disclaimer;
  } catch (_) {}
  loadChecklist();
  loadProfiles();
  // 哨兵面板的「去塔里更新」留了一个请求标记，进来就读一次，
  // 有就让隐私页的更新卡片自己滚到视野里
  refreshUpdate(true);
  startUpdatePoll();
  const hash = (location.hash || '').replace('#', '');
  const tabName = hash.split(':')[0];
  if (tabName && document.getElementById('panel-' + tabName)) switchTab(tabName);
})();
