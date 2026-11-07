/* 菜单栏工具子页：复用已有操作绑定，只显示当前分类或当前工具。 */
(() => {
  if (!EMBEDDED_TOOLS) return;
  const root = document.createElement('section');
  root.id = 'panel-tools';
  root.innerHTML = '<header class="pt-head"><button type="button" id="pt-back">‹ 哨兵</button><strong id="pt-title">全部工具</strong><span id="pt-guardstate">正在连接哨兵</span></header><main id="pt-content"></main><p id="pt-feedback" role="status" aria-live="polite"></p>';
  document.body.append(root);
  const content = document.getElementById('pt-content');
  const title = document.getElementById('pt-title');
  const back = document.getElementById('pt-back');
  const feedback = document.getElementById('pt-feedback');
  const vault = document.createElement('div');
  vault.id = 'pt-vault'; vault.hidden = true; root.append(vault);
  let page = 'index', parent = 'index', writes = 0, scanning = null;
  let needsNotice = false, deferredView = 'index';
  const originalFetch = window.fetch.bind(window);
  // 返回不能中断已确认的写入。未确认时进入工具页不执行任何修改。
  window.fetch = async function (url, options = {}) {
    const mutation = /^(POST|DELETE|PUT|PATCH)$/i.test(options.method || 'GET');
    if (mutation) { writes++; back.disabled = true; }
    try { return await originalFetch(url, options); }
    finally { if (mutation) { writes--; back.disabled = writes > 0; } }
  };
  const anchor = id => document.getElementById(id);
  const card = id => anchor(id)?.closest('.card');
  const tool = (label, nodes, load, group) => ({label, nodes, load, group});
  const scanner = document.createElement('div');
  scanner.innerHTML = '<p class="pt-desc">只读检测后，手动勾选需要处理的项目。清理仍需逐项预览和确认。</p><button type="button" id="pt-scan" class="btn sm">检测环境</button>';
  for (const id of ['filterbar','pickbar','findings']) scanner.append(anchor(id));
  scanner.querySelector('#pt-scan').addEventListener('click', () => rescan().catch(e => { feedback.textContent = e.message; }));
  const about = document.createElement('div');
  about.append(anchor('nt-body'));
  const acknowledge = document.createElement('button'); acknowledge.id = 'pt-ack'; acknowledge.type = 'button'; acknowledge.className = 'btn sm'; acknowledge.textContent = '已阅读，继续';
  about.append(acknowledge);
  acknowledge.addEventListener('click', async () => {
    try { await api('/api/notice', {method:'POST', body:{}}); needsNotice = false; show(deferredView); }
    catch(e) { feedback.textContent = e.message; }
  });
  const tools = {
    netcfg: tool('出口国家预期', [anchor('netcfg-card')], refreshNetcfg, 'network'),
    proxyfix: tool('分流与 UDP 规则', [anchor('proxyfix-card')], refreshProxyfix, 'network'),
    dns: tool('DNS 解析器', [anchor('proxyfix-dns-card'),anchor('proxyfix-preview')], refreshProxyfixDns, 'network'),
    shellproxy: tool('终端代理', [anchor('shellproxy-card')], refreshShellproxy, 'network'),
    ipv6: tool('Wi-Fi IPv6', [anchor('ipv6-card')], refreshIPv6, 'network'),
    align: tool('按出口对齐', [anchor('align-card')], refreshAlign, 'environment'),
    region: tool('区域格式', [anchor('region-card')], refreshRegion, 'environment'),
    shellenv: tool('终端时区与语言', [anchor('shellenv-card')], refreshShellenv, 'environment'),
    timezone: tool('系统时区', [card('tz-badge')], loadTz, 'environment'),
    privacy: tool('遥测隐私设置', [card('privacy-badge')], refreshPrivacy, 'privacy-group'),
    scanner: tool('检测与清理', [scanner], () => state.scan ? Promise.resolve() : rescan(), 'privacy-group'),
    isolation: tool('配置隔离', [anchor('view-isolation')], loadProfiles, 'privacy-group'),
    checklist: tool('手动核对', [anchor('panel-checklist')], loadChecklist, 'privacy-group'),
    watch: tool('遥测连接观察', [card('watch-badge')], refreshWatch, 'privacy-group'),
    hosts: tool('导出遥测主机规则', [card('hosts-block-gen')], null, 'privacy-group'),
    snapshot: tool('过滤后的安全快照', [card('snapshot-badge')], null, 'records'),
    restore: tool('备份与恢复', [card('restore-badge')], loadBackups, 'records'),
    history: tool('操作记录', [anchor('history-card')], refreshHistory, 'records'),
    egress: tool('出口记录', [card('egress-badge')], loadEgress, 'records'),
    sessionapi: tool('节点监测接口', [anchor('sessionapi-card')], refreshSessionApi, 'settings'),
    update: tool('应用更新', [anchor('update-card')], refreshUpdate, 'settings'),
    uninstall: tool('卸载与恢复', [anchor('uninstall-card')], loadUninstall, 'settings'),
    about: tool('使用说明与边界', [about], null, 'settings')
  };
  const groups = {
    network: ['网络与代理','DNS、分流、终端代理、IPv6'],
    environment: ['环境与地区','时区、语言、地区与出口对齐'],
    'privacy-group': ['隐私与清理','遥测、本地残留与配置隔离'],
    records: ['记录与恢复','操作、出口、快照与恢复'],
    settings: ['应用设置','节点接口、更新与卸载']
  };
  // 保留原节点和事件，不复制表单或敏感内容；切换时只移动当前工具。
  const moved = new Set();
  for (const entry of Object.values(tools)) for (const node of entry.nodes) if (node && !moved.has(node)) {
    vault.append(node); moved.add(node);
  }
  function hideCurrent() {
    for (const node of [...content.children]) if (moved.has(node)) vault.append(node); else node.remove();
  }
  function choice(label, detail, target) {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'pt-choice'; button.dataset.view = target;
    const text = document.createElement('span'), strong = document.createElement('strong'), sub = document.createElement('small');
    strong.textContent = label; sub.textContent = detail;
    text.append(strong, sub); button.append(text, document.createTextNode('›'));
    button.addEventListener('click', () => show(target)); return button;
  }
  async function show(next = 'index') {
    if (writes) return;
    if (needsNotice && next !== 'about') { deferredView = next; next = 'about'; }
    if (page !== next && ['dns','proxyfix'].includes(page)) anchor('proxyfix-cancel').click();
    hideCurrent(); feedback.textContent = ''; page = next;
    back.textContent = next === 'index' ? '‹ 哨兵' : '‹ 返回';
    if (next === 'index') {
      title.textContent = '全部工具'; parent = 'index';
      for (const [id, [label, desc]] of Object.entries(groups)) content.append(choice(label, desc, id));
    } else if (groups[next]) {
      title.textContent = groups[next][0]; parent = 'index';
      for (const [id, entry] of Object.entries(tools)) if (entry.group === next) content.append(choice(entry.label, '', id));
    } else if (tools[next]) {
      const entry = tools[next]; parent = entry.group; title.textContent = entry.label;
      // DNS 是原分流工具的独立子项；共用事件绑定和恢复记录。
      if (next === 'proxyfix') anchor('proxyfix-card').append(anchor('proxyfix-preview'));
      for (const node of entry.nodes) if (node) { node.classList.add('pt-active-tool'); content.append(node); }
      try { if (entry.load) await entry.load(); }
      catch (e) { feedback.textContent = '读取失败：' + e.message; }
    } else { return show('index'); }
    window.scrollTo(0, 0);
  }
  async function rescan() {
    if (scanning) return scanning;
    scanning = (async () => {
      feedback.textContent = '正在检测，未执行清理…';
      const data = await api('/api/scan', {method:'POST', body:{net:true}});
      setScan(data); feedback.textContent = '检测完成；默认不勾选清理项。';
    })();
    try { return await scanning; } finally { scanning = null; }
  }
  back.addEventListener('click', async () => {
    if (writes) return;
    if (needsNotice && page === 'about') {
      window.webkit?.messageHandlers?.shield?.postMessage({action:'back-panel'}); return;
    }
    if (page !== 'index') { show(parent); return; }
    if (watchOn) { await show('watch'); feedback.textContent = '观察代理仍在运行。可以直接收起面板；请先收哨，再关闭工具引擎。'; return; }
    if (window.webkit?.messageHandlers?.shield) window.webkit.messageHandlers.shield.postMessage({action:'back-panel'});
    else feedback.textContent = '请从菜单栏哨兵进入，以返回原生面板。';
  });
  window.PanelTools = {show, rescan};
  // 维护页收到巡检更新时只保存即时状态，不创建另一份守护仪表盘。
  window.SHIELD = {update(p) { root.dataset.monitor = p.paused ? 'paused' : p.enabled ? 'running' : 'off'; anchor('pt-guardstate').textContent = p.paused ? '值守已暂停' : p.enabled ? '后台值守中' : '值守已停用'; }};
  (async () => {
    deferredView = location.hash.slice(1) || 'index';
    try {
      const [notice, watch] = await Promise.all([api('/api/notice'), api('/api/watch')]); needsNotice = !notice.acked; watchOn = !!watch.running;
      await show(needsNotice ? 'about' : deferredView);
      window.webkit?.messageHandlers?.shield?.postMessage({action:'tools-ready'});
    } catch(e) { feedback.textContent = '读取使用说明失败，请返回后重试：' + e.message; }
  })();
})();
