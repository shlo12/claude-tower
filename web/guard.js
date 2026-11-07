/* 统一主窗口：原生哨兵决定会话状态，体检仅提供诊断。
 *
 * 守护台只在菜单栏面板里有一份，主窗口不再摆第二遍。所以这里不管
 * 「启动 / 结束会话」那套按钮——它们跟着面板走。主窗口剩下三件事：
 * 顶栏那颗结论灯、记录页的守护事件、设置页的开机启动与暂停/退出。
 */
(() => {
  if (new URLSearchParams(location.search).get("panel") === "1") return;
  const {api, esc, toast} = window.CC;
  const $ = s => document.querySelector(s);
  $('#operation-slot').append($('#history-card'));
  for (const id of ['sessionapi-card', 'update-card', 'uninstall-card']) {
    const el = document.getElementById(id);
    if (el) $('#settings-slot').append(el);
  }
  $('#open-game').addEventListener('click', () => window.Tower?.showTitle());
  let pending = false, current = null, request = 0;
  const commands = {login: 'login', pause: 'pause', resume: 'resume', quit: 'quit'};
  const prompts = {
    pause: '暂停值守 30 分钟，并结束本次戒严使用？',
    quit: '停止后台保护并结束本次戒严使用？Claude 未能退出时哨兵会继续值守。'
  };
  // 顶栏那颗结论灯。和菜单栏面板说的是同一句话，用的也是同一套颜色，
  // 所以「塔说没事、哨兵说危险」这种自相矛盾不会再出现。
  const pills = {
    watch: ['pass', '守护中'], active: ['pass', '戒严中'],
    waiting: ['warn', '待检查'], checking: ['warn', '检查中'],
    paused: ['warn', '已暂停'], off: ['warn', '已关闭']
  };
  function renderVerdict(d) {
    const [v, t] = pills[d.state] || (d.running ? ['warn', '状态未知'] : ['bad', '哨兵未运行']);
    const pill = $('#top-verdict');
    if (!pill) return;
    pill.dataset.v = v;
    $('#top-verdict-text').textContent = t;
  }
  function render(d) {
    current = d;
    renderVerdict(d);
    const available = d.supported && d.running && !pending;
    for (const key of Object.keys(commands)) {
      const el = $('#guard-' + key);
      if (el) el.disabled = !available;
    }
    const events = $('#guard-events');
    if (events) {
      events.innerHTML = (d.hits || []).slice().reverse()
        .map(x => `<li class="hist-event"><time>${esc(x.at ? new Date(x.at * 1000).toLocaleString() : '')}</time> <strong>${esc(x.kind)}</strong> ${esc(x.note)}</li>`)
        .join('') || '<li class="hist-empty">暂无守护事件</li>';
    }
    // 记录页的空态要两边一起看：这里每次重绘都要重新算一遍。
    if (typeof syncRecordsEmpty === 'function') syncRecordsEmpty();
    const resume = $('#guard-resume');
    if (resume) resume.disabled = !available || (!d.paused && d.enabled);
    const pause = $('#guard-pause');
    if (pause) pause.disabled = !available || d.paused || !d.enabled;
    const loginState = $('#guard-login-state');
    if (loginState) {
      loginState.textContent = `开机启动：${({loaded: '已加载', installed: '已安装，尚未加载', none: '未开启'})[d.login] || '未确认'}。`;
    }
  }
  async function refresh() {
    const id = ++request;
    try { const d = await api('/api/control'); if (id === request) render(d); }
    catch (_) {
      if (id === request) {
        render({supported: true, running: false, fresh: false, state: 'unknown', message: '无法连接诊断引擎；请从菜单栏确认哨兵状态。'});
      }
    }
  }
  for (const [key, action] of Object.entries(commands)) {
    const el = $('#guard-' + key);
    if (!el) continue;
    el.addEventListener('click', async () => {
      if (pending || (prompts[key] && !confirm(prompts[key]))) return;
      pending = true; if (current) render(current);
      try {
        const result = await api('/api/control', {method: 'POST', body: {action, confirm: true}});
        toast(result.message, 6000);
      } catch (e) { toast(e.message, 8000); }
      finally { pending = false; await refresh(); }
    });
  }
  window.Guard = {refresh};
  if (!TOOLS_ONLY) refresh();
  setInterval(() => { if (!document.hidden && !pending && (!TOOLS_ONLY || document.querySelector('#panel-settings.active,#panel-records.active'))) refresh(); }, 3000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
})();
