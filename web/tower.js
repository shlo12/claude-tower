/* 魔塔 · 像素闯关前端 */
(function () {
  const { api, ccHeaders, toast, esc, switchTab } = window.CC;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  const T = {
    data: null,
    floor: null,
    busy: false,
    muted: localStorage.getItem('cc-mute') === '1',
    pos: {},        // 每层勇者坐标 {f1:{x,y}, ...}
    cells: null,    // 当前层的解析后地图
    walking: false,
    lastStep: 0,
    died: false,
    auto: false,
    autoRunning: false,
    autoSkip: false,
    autoNewGear: null,
    settle: null,
    settleSel: new Set(),
    history: null,
    historyLoading: false,
    tourBusy: false,
  };

  const sleep = (ms) => new Promise((resolve) => {
    if (T.autoSkip) return resolve();
    const wait = T.auto ? Math.max(28, Math.round(ms * 0.55)) : ms;
    if (!T.auto) {
      setTimeout(resolve, wait);
      return;
    }
    // 演出中轮询跳过标记，按下「跳过演出」后不必等当前这段动画走完
    const started = performance.now();
    const tick = () => {
      if (T.autoSkip || performance.now() - started >= wait) resolve();
      else setTimeout(tick, 24);
    };
    tick();
  });

  // 跳到处理页并高亮目标卡片（例如 3-9 → 隐私设置里的 IPv6 卡片）
  function jumpToAct(tab, focus) {
    switchTab(tab || 'findings');
    if (!focus) return;
    setTimeout(() => {
      const el = document.getElementById(focus + '-card') || document.getElementById(focus);
      if (!el) return;
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.classList.remove('focus-flash');
      void el.offsetWidth;
      el.classList.add('focus-flash');
      setTimeout(() => el.classList.remove('focus-flash'), 2000);
    }, 120);
  }

  // 记住初始 hash：#tower:1-1 这类深链接要在 switchTab 改写 hash 之前抓下来
  const BOOT_HASH = location.hash || '';

  /* ---------------------------------------------------------- 楼层地图 */
  /*
   * 每层一张 13 列的俯视角地图，像老魔塔一样走格子。
   *   # 墙    . 地板   ~ 红毯   o 立柱   T 火把(墙上)
   *   E 入口/下楼   X 上楼(守卫挡着)   B 守卫站位
   *   * 塔顶封印屏障   ^ 王座   1-5 怪物（按本层 levels 顺序）
   */
  const MAPS = {
    f1: [
      '#############',
      '######X######',
      '######B######',
      '###..~~~..###',
      '##....~....##',
      '##.1..~..2.##',
      '##....~....##',
      '##.3..~..4.##',
      '##.o..~..o.##',
      '##.5..~E~..##',
      '#############',
    ],
    f2: [
      '#############',
      '#.o..#X#..o.#',
      '#.1..#B#..2.#',
      '#.o.##.##.o.#',
      '#.3.......4.#',
      '#.o.~~~~~.o.#',
      '#.5.~...~.6.#',
      '#.o.~~~~~.o.#',
      '#.7.......8.#',
      '#.o.~~~~~.o.#',
      '#....~E~....#',
      '#############',
    ],
    f3: [
      '#############',
      '#....#X#....#',
      '#..T.#B#.T..#',
      '#...A#.#....#',
      '#.1.......2.#',
      '#.o..~~~..o.#',
      '#.3.~...~.4.#',
      '#.o..~~~..o.#',
      '#.5.......6.#',
      '#.T.~~~.T...#',
      '#.7.~.8.~.9.#',
      '#....~E~....#',
      '#############',
    ],
    f4: [
      '#############',
      '#....#X#....#',
      '#...~~B~~...#',
      '#..~~###~~..#',
      '#.1~~...~~2.#',
      '#.~~..o..~~.#',
      '#.3~~.o.~~4.#',
      '#.~~..o..~~.#',
      '#.5.~...~.6.#',
      '#..~.....~..#',
      '#....~E~....#',
      '#############',
    ],
    f5: [
      '#############',
      '#.....^.....#',
      '#....~~~....#',
      '#...~~~~~...#',
      '#..~~~~~~~..#',
      '#....~~~....#',
      '#..o..~..o..#',
      '#***********#',
      '#..o..~..o..#',
      '#....~E~....#',
      '#############',
    ],
  };
  const FLOOR_ORDER = ['f1', 'f2', 'f3', 'f4', 'f5'];

  // 地图上的怪物位：1-9 用完接 A/C/D/F（跳过 B=守卫、E=入口、X=楼梯、T=火把）
  const MOB_CHARS = '123456789ACDF';
  const mobIndex = (c) => MOB_CHARS.indexOf(c);

  /* ---------------------------------------------------------- 像素精灵 */

  /* 怪物立绘：全部换成设计师 PNG（web/assets/mobs/）。
     refId = 关卡号（1-1~4-6、3-10）或守卫 id（b1~b5）。 */
  function mobArt(refId, cls = '') {
    const file = (refId === 'b5' || refId === 'final') ? 'boss-b5'
      : /^b\d$/.test(refId) ? `boss-${refId}`
        : `mob-${refId}`;
    return `<img class="mob-pic px ${cls}" src="/assets/mobs/${file}.png" alt="" draggable="false">`;
  }

  /* 魔塔式像素勇者：四阶各自一张立绘，HUD / 地图 / 战斗共用。 */
  const HERO_GLOWS = [
    'rgba(110, 140, 240, .28)',
    'rgba(120, 160, 255, .34)',
    'rgba(164, 120, 255, .38)',
    'rgba(196, 166, 255, .46)',
  ];
  const HERO_ART = [
    '/assets/knight-t0.png',
    '/assets/knight-t1.png',
    '/assets/knight-t2.png',
    '/assets/knight-t3.png',
  ];
  const HERO_TIER_NAMES = ['布衣勇者', '铁盔剑士', '缨盔骑士', '传说勇者'];

  function heroTier(kills) {
    return kills >= 10 ? 3 : kills >= 5 ? 2 : kills >= 1 ? 1 : 0;
  }

  function heroArt(kills) {
    const tier = heroTier(kills);
    return `<img class="knight" src="${HERO_ART[tier]}" width="64" height="96" alt="" draggable="false" style="--knight-glow:${HERO_GLOWS[tier]}">`;
  }


  /* ---------------------------------------------------------- 音效 */

  let ac = null;
  function actx() {
    if (!ac) {
      const C = window.AudioContext || window.webkitAudioContext;
      if (!C) return null;
      ac = new C();
    }
    return ac;
  }
  function beep(freq, dur = 0.08, type = 'square', vol = 0.05, slideTo) {
    if (T.muted) return;
    const a = actx();
    if (!a) return;
    try {
      const o = a.createOscillator();
      const g = a.createGain();
      o.type = type;
      o.frequency.setValueAtTime(freq, a.currentTime);
      if (slideTo) o.frequency.exponentialRampToValueAtTime(slideTo, a.currentTime + dur);
      g.gain.setValueAtTime(vol, a.currentTime);
      g.gain.exponentialRampToValueAtTime(0.0001, a.currentTime + dur);
      o.connect(g);
      g.connect(a.destination);
      o.start();
      o.stop(a.currentTime + dur + 0.03);
    } catch (_) {}
  }
  const sfx = {
    swing: () => beep(720, 0.06, 'square', 0.045, 240),
    hit: () => beep(190, 0.11, 'square', 0.06, 90),
    kill: () => {
      beep(520, 0.06, 'square', 0.055);
      setTimeout(() => beep(760, 0.07, 'square', 0.055), 60);
      setTimeout(() => beep(1040, 0.13, 'square', 0.045), 130);
    },
    hurt: () => beep(150, 0.2, 'sawtooth', 0.07, 55),
    levelup: () => [523, 659, 784, 1046].forEach((f, i) => setTimeout(() => beep(f, 0.11, 'triangle', 0.05), i * 85)),
    boss: () => {
      beep(90, 0.45, 'sawtooth', 0.08, 38);
      setTimeout(() => beep(60, 0.5, 'sawtooth', 0.06, 30), 220);
    },
    win: () => [523, 659, 784, 1046, 1318, 1568].forEach((f, i) => setTimeout(() => beep(f, 0.2, 'triangle', 0.06), i * 140)),
    step: () => beep(1250, 0.03, 'square', 0.018),
    bump: () => beep(110, 0.07, 'square', 0.05),
    stairs: () => beep(480, 0.09, 'triangle', 0.05, 980),
    seal: () => beep(85, 0.28, 'sawtooth', 0.06, 40),
    menu: () => beep(880, 0.04, 'square', 0.03),
    confirm: () => { beep(660, 0.05, 'square', 0.04); setTimeout(() => beep(990, 0.09, 'square', 0.04), 55); },
  };

  /* ---------------------------------------------------------- 数据 */

  // 冷启动要跑一轮网络探测（约 10 秒），期间给一条明确的进度条，
  // 只在超过 320ms 才出现，避免缓存命中时闪一下。
  let busyEl = null;
  function busyOn(text) {
    busyOff();
    const el = document.createElement('div');
    el.className = 'busy-chip';
    el.innerHTML = '<span class="loading-ring"></span><span>' + esc(text) + '</span>';
    document.body.appendChild(el);
    busyEl = el;
  }
  function busyOff() {
    if (busyEl) { busyEl.remove(); busyEl = null; }
  }

  async function load(rescan = false) {
    const timer = setTimeout(() => busyOn(rescan ? '重新探测中…（约 10 秒）' : '正在探测本机环境…'), 320);
    try {
      const d = await api('/api/tower' + (rescan ? '?rescan=1' : ''));
      apply(d);
      if (d.scan) window.CC.setScan(d.scan);
      const m = BOOT_HASH.match(/^#tower:([\w-]+)/);
      if (m && !T.booted) {
        T.booted = true;
        const id = m[1];
        if (id === 'run') { autoRun(); }
        else if (/^f[1-5]$/.test(id)) { T.floor = id; render(); }
        else if (id === 'win') { if (d.cleared) showVictory(d); }
        else if (d.floors.some((f) => f.levels.some((lv) => lv.id === id))) fight(id);
        else if (d.floors.some((f) => f.boss.id === id)) fightBoss(id);
        else if (id === 'b5') fightFinal();
      }
    } catch (e) {
      $('#hud').innerHTML = `<div class="hud-empty">读取失败：${esc(e.message)}</div>`;
    } finally {
      clearTimeout(timer);
      busyOff();
    }
  }

  function apply(d) {
    T.data = d;
    // f5 是塔顶（不在 floors 数组里），要单独放行，否则会被重置回第一层
    if (!T.floor || (T.floor !== 'f5' && !d.floors.some((f) => f.id === T.floor))) T.floor = d.current;
    if (window.CC.setUnlocked) window.CC.setUnlocked(!!d.unlocked);
    if (titleVisible()) renderMenu();
    render();
    renderBoard(d.board);
    const settlePanel = $('#panel-settle');
    if (settlePanel && settlePanel.classList.contains('active')) renderSettle();
  }

  /* ---------------------------------------------------------- 渲染 */

  function render() {
    const d = T.data;
    if (!d) return;
    renderHud(d);
    renderSpine(d);
    renderFloor(d);
    renderProgress(d);
  }

  function renderProgress(d) {
    const box = $('#floor-progress');
    if (!box) return;
    const floors = d.floors || [];
    const finalDone = !!(d.final && d.final.defeated);
    const finalReady = !!(d.final && d.final.unlocked);
    const items = floors.map((f) => {
      const pct = f.count ? Math.max(0, Math.min(100, (f.progress / f.count) * 100)) : 0;
      const state = f.cleared ? 'cleared' : f.progress ? 'partial' : 'todo';
      const boss = f.boss ? (f.boss.defeated ? '层主已破' : f.boss.unlocked ? '层主可战' : '层主封印') : '';
      return `<button class="fp-item ${state}${T.floor === f.id ? ' sel' : ''}" data-floor="${f.id}"
          title="第 ${f.no} 层 · ${esc(f.name)} · ${f.progress}/${f.count} 关 · ${boss}">
        <span class="fp-no">0${f.no}</span>
        <span class="fp-main"><b>${esc(f.name)}</b><span class="fp-bar"><i style="width:${pct}%"></i></span></span>
        <span class="fp-count"><b>${f.progress}</b>/${f.count}</span>
      </button>`;
    });
    items.push(`<button class="fp-item final ${finalDone ? 'cleared' : finalReady ? 'ready' : 'todo'}${T.floor === 'f5' ? ' sel' : ''}" data-floor="f5"
        title="塔顶 · ${finalDone ? '已通关' : finalReady ? '塔主已解封' : '封印中'}">
      <span class="fp-no">05</span>
      <span class="fp-main"><b>塔顶</b><span class="fp-bar"><i style="width:${finalDone ? 100 : 0}%"></i></span></span>
      <span class="fp-count"><b>${finalDone ? 1 : 0}</b>/1</span>
    </button>`);
    box.innerHTML = `
      <div class="fp-head">
        <span>本局闯关进度</span>
        <span><b>${d.hud.defeated}</b> / ${d.hud.total} 关 · 层主 ${floors.filter((f) => f.boss && f.boss.defeated).length}/4</span>
      </div>
      <div class="fp-grid">${items.join('')}</div>`;
    $$('.fp-item', box).forEach((el) => el.addEventListener('click', () => {
      T.floor = el.dataset.floor;
      render();
    }));
  }

  const GEAR_ICONS = {
    atk: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M4.2 19.8 3 21l-1-3 1.4-2.4L16 3h4l1 4L8.6 19.6l-3 1.2ZM15.6 6.4l2 2"/></svg>',
    def: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 2 4 5.5v6.2c0 4.6 3.2 8.9 8 10.3 4.8-1.4 8-5.7 8-10.3V5.5L12 2Zm-1 13.4-3.2-3.2 1.4-1.4 1.8 1.8 4.4-4.4 1.4 1.4-5.8 5.8Z"/></svg>',
    hp: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 21s-8-5-8-11a4.5 4.5 0 0 1 8-2.8A4.5 4.5 0 0 1 20 10c0 6-8 11-8 11Z"/></svg>',
  };
  const GEAR_SLOTS = ['f1', 'f2', 'f3', 'f4'];

  function gearGrid(gear) {
    const items = gear || [];
    return `<div class="gear-grid">${GEAR_SLOTS.map((fid, i) => {
      const g = items.find((x) => x.floorId === fid || x.floor === i + 1);
      const no = `0${i + 1}`;
      if (!g) {
        return `<div class="gear-slot empty" title="清空第 ${i + 1} 层的小怪后解锁">
          <span class="gs-no">${no}</span>
          <span class="gs-ico">—</span>
          <span class="gs-main"><b>未解锁</b><span>清空本层</span></span>
        </div>`;
      }
      return `<div class="gear-slot filled s-${g.stat}${T.autoNewGear === g.floorId ? ' new' : ''}" title="${esc(g.label)} +${g.value} · 第 ${i + 1} 层">
        <span class="gs-no">${no}</span>
        <span class="gs-ico">${GEAR_ICONS[g.stat] || ''}</span>
        <span class="gs-main"><b>${esc(g.name)}</b><span>${esc(g.label)} +${g.value}</span></span>
      </div>`;
    }).join('')}</div>`;
  }

  function renderHud(d) {
    const h = d.hud;
    const sv = d.survival || {};
    const hpPct = Math.max(0, Math.min(100, (h.hp / h.hpMax) * 100));
    const dead = h.hp <= 0;
    const tier = heroTier(h.defeated);

    $('#hud').innerHTML = `
      <div class="hud-hero${dead ? ' down' : ''}" style="--knight-glow:${HERO_GLOWS[tier]}">
        <button class="hud-mute" id="hud-mute" title="${T.muted ? '开启音效' : '关闭音效'}">${T.muted ? '静' : '♪'}</button>
        <span class="hud-lv-badge">Lv.${h.level}</span>
        ${heroArt(h.defeated)}
        <span class="hud-hero-name">${HERO_TIER_NAMES[tier]}</span>
      </div>

      <div class="hud-ident">
        <div class="hud-name">勇者${dead ? '<span class="hud-dead">已倒下</span>' : ''}</div>
        <div class="hud-title">${esc(h.title)} · 击杀 ${h.defeated}/${h.total}</div>
      </div>

      <div class="hud-bar hp ${hpPct <= 25 ? 'low' : ''}">
        <i style="width:${hpPct}%"></i>
        <span>HP ${h.hp} / ${h.hpMax}</span>
      </div>

      ${dead
        ? (T.autoRunning
          ? `<div class="hud-heal auto"><b>演示中倒下</b><span>即将自动回城</span></div>`
          : `<button class="hud-heal danger" id="hud-heal"><b>回城休整</b><span>生命归零，回满 ${h.hpMax}</span></button>`)
        : h.hp < h.hpMax
          ? (T.autoRunning
            ? ''
            : `<button class="hud-heal" id="hud-heal"><b>回城休整</b><span>${h.hp} / ${h.hpMax} → 回满</span></button>`)
          : ''}

      <div class="stat-row">
        <div class="stat atk"><em>ATK</em><b>${h.atk}</b></div>
        <div class="stat def"><em>DEF</em><b>${h.def}</b></div>
        <div class="stat kill"><em>击杀</em><b>${h.defeated}<small>/${h.total}</small></b></div>
      </div>

      <div class="hud-bar exp">
        <i style="width:${h.expPct}%"></i>
        <span>EXP ${h.expIn} / ${h.expNeed}</span>
      </div>

      ${gearGrid(d.gear)}

      <div class="hud-foot">
        <span>存活 ${sv.days == null ? '—' : sv.days} 天</span>
        <span>${h.deaths ? `阵亡 ${h.deaths} 次` : ''}</span>
      </div>
      <button class="hud-reset" id="hud-reset"${T.autoRunning ? ' disabled' : ''}>重开一局</button>`;

    const mute = $('#hud-mute');
    if (mute) {
      mute.addEventListener('click', () => {
        T.muted = !T.muted;
        localStorage.setItem('cc-mute', T.muted ? '1' : '0');
        renderHud(d);
      });
    }
    const heal = $('#hud-heal');
    if (heal) heal.addEventListener('click', healUp);
    const reset = $('#hud-reset');
    if (reset && !T.autoRunning) {
      reset.addEventListener('click', async () => {
        if (!confirm('重开一局？已击败的怪物会全部复活，战绩不受影响。')) return;
        try {
          const res = await api('/api/tower/reset', { method: 'POST', body: {} });
          T.data = res.state;
          T.floor = res.state.current;
          render();
          toast('新的一局开始了');
        } catch (e) { toast(e.message); }
      });
    }
  }

  function renderSpine(d) {
    const order = [...d.floors].reverse();
    const final = d.final;
    const top = `
      <button class="spine-top ${final.defeated ? 'cleared' : final.unlocked ? 'ready' : 'locked'} ${T.floor === 'f5' ? 'sel' : ''}" data-floor="f5">
        <span class="sp-flag">塔顶</span>
        <span class="sp-stat ${final.defeated ? 'ok' : 'todo'}">${final.defeated ? '通关' : '未通关'}</span>
        <span class="sp-crown">${final.defeated ? '☠' : '♛'}</span>
      </button>`;
    const items = order.map((f) => {
      const state = f.cleared ? 'cleared' : f.id === d.current ? 'current' : 'todo';
      return `<button class="spine-item ${state} ${f.id === T.floor ? 'sel' : ''}" data-floor="${f.id}">
        <span class="sp-no">0${f.no}</span>
        <span class="sp-name">${esc(f.name)}</span>
        <span class="sp-prog">${f.progress}/${f.count}</span>
        <span class="sp-stat ${f.cleared ? 'ok' : 'todo'}">${f.cleared ? '通关' : '未通关'}</span>
      </button>`;
    }).join('');
    $('#spine').innerHTML = top + `<div class="spine-line"></div>` + items;
  }

  /* ---------------------------------------------------------- 地图引擎 */

  function mapCells(fid) {
    const rows = MAPS[fid];
    const w = Math.max(...rows.map((r) => r.length));
    return { w, h: rows.length, rows: rows.map((r) => r.padEnd(w, '#')) };
  }

  function findChar(fid, ch) {
    const c = mapCells(fid);
    for (let y = 0; y < c.h; y++) {
      const x = c.rows[y].indexOf(ch);
      if (x >= 0) return { x, y };
    }
    return { x: 1, y: c.h - 2 };
  }

  function finalFloor(d) {
    const f = d.final;
    return {
      id: 'f5', no: 5, name: '塔顶', subtitle: 'BOSS', tint: f.tint,
      story: f.defeated
        ? '塔顶的灯灭了。这里现在只剩你的名字。'
        : f.unlocked
          ? '四层守卫全部倒下。它就在上面，等你。'
          : '先把下面四层的守卫全部击倒，塔顶才会开门。',
      levels: [], boss: null, final: f, cleared: f.defeated,
    };
  }

  function curFloor() {
    const d = T.data;
    if (!d) return null;
    if (T.floor === 'f5') return finalFloor(d);
    return d.floors.find((x) => x.id === T.floor) || d.floors[0];
  }

  function cellAt(x, y) {
    return (T.cells.rows[y] || '')[x] || '#';
  }

  // 能不能站上去（不触发任何东西的可行走格）
  function walkableChar(c, f, d) {
    if (!c || '#oT'.includes(c)) return false;
    if (c === '*') return d.final.unlocked || d.final.defeated;
    const mi = mobIndex(c);
    if (mi >= 0) {
      const lv = (f.levels || [])[mi];
      return !lv || lv.defeated;
    }
    if (c === 'B') return !f.boss || f.boss.defeated;
    if (c === '^') return d.final.defeated;
    return true;   // . ~ , E X
  }

  function setFacing(dir) {
    const el = $('#fmap .hdir');
    if (el) el.classList.toggle('flip', dir < 0);
  }

  function positionHero() {
    const el = $('#fmap .pc');
    const p = T.pos[T.floor];
    if (el && p) {
      el.style.setProperty('--x', p.x);
      el.style.setProperty('--y', p.y);
    }
  }

  // 下楼落脚点：X 三面是墙，落楼梯上会卡死，落到守卫面前的空位
  function downSpawn(fid) {
    const c = mapCells(fid);
    const b = findChar(fid, 'B');
    for (const [dx, dy] of [[0, 1], [-1, 0], [1, 0]]) {
      const x = b.x + dx, y = b.y + dy;
      const ch = (c.rows[y] || '')[x];
      if (ch && !'#oTBX*'.includes(ch) && mobIndex(ch) < 0) return { x, y };
    }
    return { x: b.x, y: b.y + 1 };
  }

  function transport(dir) {
    const i = FLOOR_ORDER.indexOf(T.floor);
    const j = dir === 'up' ? i + 1 : i - 1;
    if (j < 0 || j >= FLOOR_ORDER.length) return false;
    const to = FLOOR_ORDER[j];
    // 上楼落在下一层的入口 E，下楼落在上一层守卫面前
    T.pos[to] = dir === 'up' ? findChar(to, 'E') : downSpawn(to);
    T.floor = to;
    sfx.stairs();
    render();
    return true;
  }

  // 移动原语：尝试走进 (nx,ny)。返回 'walk' | 'tp' | 'fight' | false
  function tryStep(nx, ny) {
    const d = T.data;
    const f = curFloor();
    if (!d || !f) return false;
    if (downed()) {
      toast('你已经倒下了，先回城休整');
      sfx.bump();
      return false;
    }
    const c = cellAt(nx, ny);
    const p = T.pos[T.floor];

    if (c === '#' || c === 'o' || c === 'T') { sfx.bump(); return false; }

    if (c === '*') {
      if (!d.final.unlocked && !d.final.defeated) {
        toast('塔顶封印中——四层守卫全灭之前，这道光幕不会开');
        sfx.seal();
        return false;
      }
      return stepTo(nx, ny);
    }

    const mi = mobIndex(c);
    if (mi >= 0) {
      const lv = (f.levels || [])[mi];
      if (lv && !lv.defeated) {
        if (p && nx !== p.x) setFacing(Math.sign(nx - p.x));
        fight(lv.id);
        return 'fight';
      }
      return stepTo(nx, ny);
    }

    if (c === 'B' && f.boss && !f.boss.defeated) {
      if (p && nx !== p.x) setFacing(Math.sign(nx - p.x));
      if (f.boss.unlocked) {
        fightBoss(f.boss.id);
      } else {
        toast(`${f.boss.name}还在沉睡——清空本层 ${f.count} 只怪物后现身`);
        sfx.seal();
      }
      return 'fight';
    }

    if (c === '^') {
      if (d.final.defeated) { showVictory(d); return 'fight'; }
      if (d.final.unlocked) {
        if (p && nx !== p.x) setFacing(Math.sign(nx - p.x));
        fightFinal();
        return 'fight';
      }
      return false;
    }

    if (c === 'X') {
      if (f.boss && !f.boss.defeated) {
        toast('阶梯被守卫的力量封住了');
        sfx.seal();
        return false;
      }
      transport('up');
      return 'tp';
    }

    if (c === 'E') {
      if (T.floor === 'f1') {
        toast('身后就是城门，塔外没有答案');
        sfx.bump();
        return false;
      }
      transport('down');
      return 'tp';
    }

    return stepTo(nx, ny);
  }

  function stepTo(nx, ny) {
    const p = T.pos[T.floor];
    if (p && nx !== p.x) setFacing(Math.sign(nx - p.x));
    T.pos[T.floor] = { x: nx, y: ny };
    sfx.step();
    positionHero();
    return 'walk';
  }

  function bfsPath(sx, sy, tx, ty, f, d) {
    const key = (x, y) => x + ',' + y;
    const seen = new Set([key(sx, sy)]);
    const prev = {};
    const q = [[sx, sy]];
    while (q.length) {
      const [x, y] = q.shift();
      if (x === tx && y === ty) {
        const path = [];
        let k = key(x, y);
        while (prev[k]) { path.unshift(prev[k].to); k = prev[k].from; }
        return path;
      }
      for (const [nx, ny] of [[x + 1, y], [x - 1, y], [x, y + 1], [x, y - 1]]) {
        const k = key(nx, ny);
        if (seen.has(k)) continue;
        if (!walkableChar(cellAt(nx, ny), f, d)) continue;
        seen.add(k);
        prev[k] = { from: key(x, y), to: { x: nx, y: ny } };
        q.push([nx, ny]);
      }
    }
    return null;
  }

  async function walkTo(tx, ty) {
    if (T.walking || T.busy || battleOpen || T.autoRunning) return;
    const d = T.data;
    const f = curFloor();
    const p = T.pos[T.floor];
    if (!d || !f || !p) return;
    if (downed()) {
      toast('你已经倒下了，先回城休整');
      return;
    }
    const c = cellAt(tx, ty);
    if (tx === p.x && ty === p.y) return;

    let path = null;
    let bumpInto = false;
    if (walkableChar(c, f, d)) {
      path = bfsPath(p.x, p.y, tx, ty, f, d);
    }
    if (!path) {
      // 目标格被实体占着：走到它旁边再撞上去
      let best = null;
      for (const [nx, ny] of [[tx + 1, ty], [tx - 1, ty], [tx, ty + 1], [tx, ty - 1]]) {
        if (!walkableChar(cellAt(nx, ny), f, d)) continue;
        const pp = bfsPath(p.x, p.y, nx, ny, f, d);
        if (pp && (!best || pp.length < best.length)) best = pp;
      }
      path = best;
      bumpInto = true;
    }
    if (!path) { sfx.bump(); return; }

    T.walking = true;
    try {
      for (const s of path) {
        const r = tryStep(s.x, s.y);
        if (r !== 'walk') return;
        await sleep(135);
      }
      if (bumpInto) {
        await sleep(60);
        tryStep(tx, ty);
      }
    } finally {
      T.walking = false;
    }
  }

  /* ---------------------------------------------------------- 楼层渲染 */

  function carpetClass(cells, x, y) {
    const L = cells.rows[y][x - 1], R = cells.rows[y][x + 1];
    const U = (cells.rows[y - 1] || '')[x], D = (cells.rows[y + 1] || '')[x];
    return (L === '~' || R === '~') && U !== '~' && D !== '~' ? 'c ch' : 'c';
  }

  function cellClass(cells, c, x, y, f, d) {
    switch (c) {
      case 'T': return 'w torch';
      case '#': return 'w';
      case 'o': return 'f pil';
      case '~': return carpetClass(cells, x, y);
      case 'E': return 'f e';
      case 'X': return 'f x' + (f.boss && !f.boss.defeated ? ' sealed' : '');
      case '*': return (d.final.unlocked || d.final.defeated) ? 'f seal open' : 'f seal';
      case '^': return 'c t' + (d.final.defeated ? ' empty' : '');
      case 'B': return 'f b';
      default: return 'f' + ((x + y) % 2 ? ' alt' : '');
    }
  }

  function renderFloor(d) {
    const f = curFloor();
    const cells = mapCells(f.id);
    T.cells = cells;
    const is5 = f.id === 'f5';
    const lvs = f.levels || [];

    let cellHtml = '';
    cells.rows.forEach((row, y) => {
      [...row].forEach((c, x) => {
        cellHtml += `<div class="fc ${cellClass(cells, c, x, y, f, d)}"></div>`;
      });
    });

    let entHtml = '';
    cells.rows.forEach((row, y) => {
      [...row].forEach((c, x) => {
        if (mobIndex(c) >= 0) {
          const lv = lvs[mobIndex(c)];
          if (lv && !lv.defeated) {
            const st = lv.revived ? 'revived' : lv.fought ? 'hurt' : '';
            const tag = lv.revived ? ' · 复活' : lv.fought ? ' · 未击杀' : '';
            entHtml += `<div class="fent mob ${st}" data-mob="${lv.id}" style="--x:${x};--y:${y}">
              <span class="mob-tag">${esc(lv.monster.name)}${tag}</span>
              ${mobArt(lv.id)}
            </div>`;
          }
        } else if (c === 'B' && f.boss && !f.boss.defeated) {
          const st = f.boss.unlocked ? 'ready' : 'sleep';
          entHtml += `<div class="fent boss ${st}" style="--x:${x};--y:${y}">
            <span class="mob-tag">${f.boss.unlocked ? '⚔ ' : '💤 '}${esc(f.boss.name)}</span>
            ${mobArt(f.boss.id, 'big')}
          </div>`;
        } else if (c === '^' && !d.final.defeated) {
          entHtml += `<div class="fent boss ready throne" style="--x:${x};--y:${y}">
            <span class="mob-tag">${esc(d.final.name)}</span>
            ${mobArt('b5', 'big')}
          </div>`;
        }
      });
    });

    if (!T.pos[f.id]) T.pos[f.id] = findChar(f.id, 'E');
    const hp = T.pos[f.id];
    entHtml += `<div class="fent pc" style="--x:${hp.x};--y:${hp.y}"><div class="hdir">${heroArt(d.hud.defeated)}</div></div>`;

    const head = is5 ? `
      <div class="fh-right">
        <div class="fh-prog"><b>${d.floors.filter((x) => x.cleared).length}</b> / 4 守卫</div>
        ${f.cleared ? `<button class="btn sm" id="v-open-map">通关战绩</button>` : ''}
      </div>` : `
      <div class="fh-right">
        <div class="fh-prog"><b>${f.progress}</b> / ${f.count}</div>
        <button class="btn sm" data-retry="${f.id}">重闯本层</button>
      </div>`;

    $('#floor-body').innerHTML = `
      <div class="floor-head">
        <div class="fh-left">
          <div class="fh-kicker">第 ${f.no} 层 · ${esc(f.subtitle)}</div>
          <h2 class="fh-title">${esc(f.name)}</h2>
          <p class="fh-story">${esc(f.story)}</p>
        </div>
        ${head}
      </div>
      <div class="map-wrap">
        <div class="fmap${is5 ? ' f5' : ''}" id="fmap" style="--w:${cells.w}">
          ${cellHtml}${entHtml}
        </div>
      </div>
      <div class="map-tip">${is5
        ? '走上红毯，直面塔主。'
        : '方向键 / WASD 移动 · 点击地面自动寻路 · 撞上怪物即出招 · E 下楼 X 上楼'}</div>`;

    const vopen = $('#v-open-map');
    if (vopen) vopen.addEventListener('click', () => showVictory(T.data));
  }

  /* ---------------------------------------------------------- 战斗 */

  let battleOpen = false;

  function downed() {
    return !!(T.data && T.data.hud && T.data.hud.hp <= 0);
  }

  function openBattle(kind, monster, kicker, refId) {
    battleOpen = true;
    $('#battle').hidden = false;
    document.body.classList.add('battling');
    $('#b-kicker').textContent = kicker;
    $('#b-foe').innerHTML = mobArt(refId, kind === 'level' ? '' : 'big');
    $('#b-foe-side').className = 'fighter foe' + (kind === 'level' ? '' : ' boss');
    $('#b-fname').textContent = monster.name;
    $('#b-hero').innerHTML = heroArt(T.data.hud.defeated);
    $('#b-log').innerHTML = '';
    $('#b-result').hidden = true;
    $('#b-result').innerHTML = '';
    $('#b-actions').innerHTML = '';
    setFoeHp(100, 100);
    setMyHp(T.data.hud.hp, T.data.hud.hpMax);
    if (kind !== 'level') sfx.boss();
  }

  function closeBattle(force = false) {
    if (T.autoRunning && !force) return;
    if (!force && downed()) {
      healUp();
      return;
    }
    battleOpen = false;
    $('#battle').hidden = true;
    document.body.classList.remove('battling');
    $('#battle-inner').classList.remove('shake');
    // 阵亡会被抬回本层入口
    if (T.died) {
      T.died = false;
      T.pos[T.floor] = findChar(T.floor, 'E');
      render();
      toast('你被抬回了本层入口');
    }
  }

  function setFoeHp(v, max) {
    const pct = Math.max(0, Math.min(100, (v / max) * 100));
    $('#b-foe-hp').style.width = pct + '%';
    $('#b-foe-hp-t').textContent = Math.max(0, Math.round(v));
  }
  function setMyHp(v, max) {
    const pct = Math.max(0, Math.min(100, (v / max) * 100));
    $('#b-me-hp').style.width = pct + '%';
    $('#b-me-hp-t').textContent = Math.max(0, Math.round(v));
  }

  function log(text, cls = '') {
    const line = document.createElement('div');
    line.className = 'b-line ' + cls;
    line.innerHTML = text;
    $('#b-log').appendChild(line);
    $('#b-log').scrollTop = $('#b-log').scrollHeight;
  }

  function floatNum(side, text, cls) {
    const host = side === 'foe' ? $('#b-foe-side') : $('#b-me-side');
    const n = document.createElement('span');
    n.className = 'dmg ' + cls;
    n.textContent = text;
    host.appendChild(n);
    setTimeout(() => n.remove(), 900);
  }

  function slash() {
    const s = document.createElement('div');
    s.className = 'slash';
    $('#stage').appendChild(s);
    setTimeout(() => s.remove(), 420);
  }

  function burst(host, tint) {
    for (let i = 0; i < 14; i++) {
      const p = document.createElement('span');
      p.className = 'spark';
      const a = (Math.PI * 2 * i) / 14 + Math.random() * 0.4;
      const d = 40 + Math.random() * 70;
      p.style.setProperty('--dx', `${Math.cos(a) * d}px`);
      p.style.setProperty('--dy', `${Math.sin(a) * d}px`);
      p.style.background = tint;
      host.appendChild(p);
      setTimeout(() => p.remove(), 700);
    }
  }

  function shake() {
    const el = $('#battle-inner');
    el.classList.remove('shake');
    void el.offsetWidth;
    el.classList.add('shake');
  }

  async function playLevel(b) {
    const foe = $('#b-foe-side');
    openBattle('level', b.monster, `第 ${b.id.split('-')[0]} 层 · 小关 ${b.id}`, b.id);
    // 战斗从「打之前」的血量起算，否则会先跳到战后血量再往回扣
    setMyHp(b.hudBefore.hp, b.hudBefore.hpMax);
    log(`<b>${esc(b.monster.name)}</b> 拦住了去路。`);
    await sleep(420);

    log('你挥剑砍了上去。', 'me');
    $('#b-hero').classList.add('lunge');
    sfx.swing();
    await sleep(150);
    slash();
    await sleep(110);
    $('#b-hero').classList.remove('lunge');
    foe.classList.add('hit');
    sfx.hit();
    await sleep(320);
    foe.classList.remove('hit');

    if (b.killed) {
      setFoeHp(0, b.monsterHp);
      floatNum('foe', `-${b.monsterHp}`, 'crit');
      burst(foe, b.monster.tint);
      foe.classList.add('dead');
      sfx.kill();
      await sleep(520);
      log(`<b class="ok">击杀！</b> ${esc(b.monster.name)} 消散了。`, 'ok');
      if (b.heal) {
        floatNum('me', `+${b.heal}`, 'heal');
        log(`拾起战利品，回复 ${b.heal} 点生命。`, 'gold');
      }
      if (b.exp) floatNum('foe', `+${b.exp} EXP`, 'exp');
      if (b.gearNew && b.gearNew.length) {
        b.gearNew.forEach((g) => log(`获得装备 <b class="gold">${esc(g.name)}</b> · ${esc(g.label)} +${g.value}`, 'gold'));
        sfx.levelup();
      }
    } else {
      log(`你的攻击力 ${b.atk} 打在它身上，几乎没留下痕迹。`, 'hint');
      await sleep(380);

      const hits = b.hits && b.hits.length ? b.hits : [b.dmg];
      let hp = b.hudBefore.hp;
      for (let i = 0; i < hits.length; i++) {
        log(`<b>${esc(b.monster.name)}</b> 反击！`, 'foe');
        foe.classList.add('counter');
        sfx.hurt();
        shake();
        await sleep(170);
        hp = Math.max(0, hp - hits[i]);
        setMyHp(hp, b.hudBefore.hpMax);
        floatNum('me', `-${hits[i]}`, 'hurt');
        $('#b-me-side').classList.add('hit');
        await sleep(370);
        foe.classList.remove('counter');
        $('#b-me-side').classList.remove('hit');
      }

      if (b.dead) {
        log('<b class="bad">你被打倒了，眼前一黑。</b>', 'bad');
        $('#b-me-side').classList.add('down');
        sfx.hurt();
        shake();
        await sleep(620);
      } else {
        log(`你拖着 ${b.hpAfter} 点血退了下来。`, 'hint');
      }
      if (b.dead) T.died = true;
    }

    if (b.levelUp) {
      sfx.levelup();
      log(`<b class="gold">升级！</b> 你现在是 Lv.${b.hud.level} ${esc(b.hud.title)}`, 'gold');
      burst($('#b-hero').parentElement, '#ffd66b');
    }
    await sleep(240);
    showResult(b);
  }

  async function playBoss(b) {
    const foe = $('#b-foe-side');
    openBattle('boss', b.monster, b.kind === 'final' ? '塔顶 · 最终 BOSS' : '本层守卫', b.id);
    setMyHp(b.hudBefore.hp, b.hudBefore.hpMax);
    log(`<b class="gold">${esc(b.monster.name)}</b> 站了起来。`, 'gold');
    await sleep(600);

    const rounds = b.kind === 'final' ? 4 : 3;
    for (let i = 0; i < rounds; i++) {
      log('你蓄力一击。', 'me');
      $('#b-hero').classList.add('lunge');
      sfx.swing();
      await sleep(150);
      slash();
      await sleep(110);
      $('#b-hero').classList.remove('lunge');
      foe.classList.add('hit');
      sfx.hit();
      shake();
      const left = Math.round(b.monsterHp * (1 - (i + 1) / rounds));
      setFoeHp(left, b.monsterHp);
      floatNum('foe', `-${Math.round(b.monsterHp / rounds)}`, 'crit');
      await sleep(380);
      foe.classList.remove('hit');
    }

    burst(foe, b.monster.tint);
    burst(foe, '#ffd66b');
    foe.classList.add('dead');
    sfx.kill();
    await sleep(700);
    log(`<b class="ok">${esc(b.monster.name)} 倒下了。</b>`, 'ok');
    if (b.gearNew && b.gearNew.length) {
      b.gearNew.forEach((g) => log(`战利品：<b class="gold">${esc(g.name)}</b> · ${esc(g.label)} +${g.value}`, 'gold'));
    }
    await sleep(320);
    showResult(b);
  }

  function sevLabel(sev) {
    const map = { critical: '致命', high: '高危', medium: '中危', low: '偏低', info: '信息', pass: '通过' };
    return map[sev] || sev;
  }

  function showResult(b) {
    const box = $('#b-result');
    box.hidden = false;
    const p = b.probe || {};
    const ev = (p.evidence || []).slice(0, 6).map((e) =>
      `<div class="br-ev-row"><span>${esc(e.label)}</span><b>${esc(e.value)}</b></div>`).join('');

    box.innerHTML = `
      <div class="br-head">
        <span class="br-verdict ${b.killed ? 'ok' : b.dead ? 'dead' : 'bad'}">${b.killed ? '击杀' : b.dead ? '阵亡' : '未击杀'}</span>
        <b>${esc(b.killed ? '检测通过' : b.dead ? '你被怪物击倒了' : '检测未通过')}</b>
        <span class="br-sev s-${p.sev || 'info'}">${sevLabel(p.sev)}</span>
      </div>
      <div class="br-body">
        <p class="br-value">${esc(p.value || '')}</p>
        ${ev ? `<div class="br-ev">${ev}</div>` : ''}
        ${p.advice ? `<p class="br-advice">${esc(p.advice)}</p>` : ''}
        ${b.dead ? `<p class="br-advice" style="color:#ff9c9c">生命归零。回城休整可以回满血，但阵亡次数会记在战绩里。</p>` : ''}
      </div>`;

    const acts = $('#b-actions');
    if (T.auto) {
      acts.innerHTML = `<span class="br-auto"><i></i>自动演示中 · 即将继续</span>`;
      return;
    }
    const btns = [];
    if (b.killed) {
      btns.push(`<button class="btn primary" data-close="1">继续探索</button>`);
    } else if (b.dead || downed()) {
      btns.push(`<button class="btn primary" data-heal="1">回城休整</button>`);
    } else {
      btns.push(`<button class="btn primary" data-refight="${b.id}">修好了，再战</button>`);
      if (T.data.unlocked) {
        if (b.kind === 'level' && (b.fixIds || []).length) {
          btns.push(`<button class="btn" data-act-clean="1">直接清理残留</button>`);
        }
      }
      if (b.act && b.act.kind === 'open') {
        btns.push(`<button class="btn" data-act-open="${esc(b.act.pane || 'general')}">${esc(b.act.label || '打开对应设置')}</button>`);
      }
      if (b.act && b.act.kind === 'profile') {
        btns.push(`<button class="btn" data-act-profile="1">${esc(b.act.label || '一键建隔离配置档')}</button>`);
      }
      if (b.act && b.act.kind === 'tour') {
        btns.push(`<button class="btn" data-act-tour="1">${esc(b.act.label || '开始全塔挑战')}</button>`);
      }
      if (b.act && b.act.kind === 'site') {
        btns.push(`<button class="btn" data-site="1">${esc(b.act.label || '打开检测网站')}</button>`);
      }
      if (b.act && b.act.kind === 'goto') {
        btns.push(`<button class="btn" data-goto="${esc(b.act.tab || 'findings')}" data-focus="${esc(b.act.focus || '')}">${esc(b.act.label || '去处理')}</button>`);
      }
      if (b.act && b.act.kind === 'openfile') {
        btns.push(`<button class="btn" data-act-file="${esc(b.act.file || '')}">${esc(b.act.label || '打开文件')}</button>`);
      }
      if (b.act && b.act.kind === 'probe') {
        btns.push(`<button class="btn" data-act-probe="1">${esc(b.act.label || '在本机浏览器里实测')}</button>`);
      }
      if (b.id === '3-2' && !(b.act && b.act.kind === 'site')) btns.push(`<button class="btn" data-site="1">打开检测网站</button>`);
      btns.push(`<button class="btn ghost" data-close="1">先撤</button>`);
    }
    acts.innerHTML = btns.join('');

    acts.querySelectorAll('[data-close]').forEach((el) => el.addEventListener('click', () => {
      closeBattle();
      if (b.kind === 'final') showVictory(T.data, { animate: true });
    }));
    acts.querySelectorAll('[data-refight]').forEach((el) => el.addEventListener('click', () => fight(el.dataset.refight)));
    acts.querySelectorAll('[data-heal]').forEach((el) => el.addEventListener('click', healUp));
    acts.querySelectorAll('[data-goto]').forEach((el) => el.addEventListener('click', () => {
      closeBattle();
      jumpToAct(el.dataset.goto, el.dataset.focus);
    }));
    acts.querySelectorAll('[data-act-open]').forEach((el) => el.addEventListener('click', () => {
      api('/api/open', { method: 'POST', body: { pane: el.dataset.actOpen } })
        .then(() => toast('已在系统设置里打开对应面板'))
        .catch((e) => toast(e.message));
    }));
    const ap = acts.querySelector('[data-act-profile]');
    if (ap) ap.addEventListener('click', () => { closeBattle(); quickProfile(); });
    const at = acts.querySelector('[data-act-tour]');
    if (at) at.addEventListener('click', () => { closeBattle(); autoRun(); });
    const ac = acts.querySelector('[data-act-clean]');
    if (ac) ac.addEventListener('click', () => {
      const ids = b.fixIds || [];
      closeBattle();
      const n = window.CC.selectForClean(ids);
      toast(n ? '已把可清理项放进清单，确认后净化' : '没有可清理项');
    });
    acts.querySelectorAll('[data-act-file]').forEach((el) => el.addEventListener('click', () => {
      api('/api/open', { method: 'POST', body: { file: el.dataset.actFile } })
        .then(() => toast('已用文本编辑打开文件'))
        .catch((e) => toast(e.message));
    }));
    const apb = acts.querySelector('[data-act-probe]');
    if (apb) apb.addEventListener('click', () => {
      closeBattle();
      if (window.CC && window.CC.runWebrtcProbe) window.CC.runWebrtcProbe();
      else toast('页面还没准备好，刷新后再试');
    });
    const site = acts.querySelector('[data-site]');
    if (site) site.addEventListener('click', async () => {
      try {
        await api('/api/open', { method: 'POST', body: { url: 'https://ip.net.coffee/claude/' } });
        toast('已在浏览器打开检测网站');
      } catch (e) { toast(e.message); }
    });

    if (b.kind === 'final') {
      const close = acts.querySelector('[data-close]');
      if (close) close.textContent = '登上勇士榜';
    }
  }

  async function healUp() {
    if (T.busy || T.autoRunning) return;
    T.busy = true;
    try {
      const res = await api('/api/tower/heal', { method: 'POST', body: {} });
      T.data = res.state;
      T.died = false;
      closeBattle(true);
      if (T.pos[T.floor]) T.pos[T.floor] = findChar(T.floor, 'E');
      render();
      sfx.levelup();
      toast('回城休整，生命已回满');
    } catch (e) {
      toast(e.message);
    } finally {
      T.busy = false;
    }
  }

  async function fight(id) {
    if (T.busy || T.autoRunning) return;
    if (downed()) { toast('你已经倒下了，先回城休整'); return; }
    T.busy = true;
    tlLoad(true, '出招中');
    try {
      const res = await api('/api/tower/fight', { method: 'POST', body: { id } });
      tlLoad(false);
      T.data = res.state;
      render();
      await playLevel(res.battle);
    } catch (e) {
      toast(e.message);
    } finally {
      T.busy = false;
      tlLoad(false);
    }
  }

  async function fightBoss(id) {
    if (T.busy || T.autoRunning) return;
    if (downed()) { toast('你已经倒下了，先回城休整'); return; }
    T.busy = true;
    tlLoad(true, '挑战层主');
    try {
      const res = await api('/api/tower/boss', { method: 'POST', body: { id } });
      tlLoad(false);
      T.data = res.state;
      render();
      await playBoss(res.battle);
    } catch (e) {
      toast(e.message);
    } finally {
      T.busy = false;
      tlLoad(false);
    }
  }

  async function fightFinal() {
    if (T.busy || T.autoRunning) return;
    if (downed()) { toast('你已经倒下了，先回城休整'); return; }
    T.busy = true;
    tlLoad(true, '登上塔顶');
    try {
      const res = await api('/api/tower/final', { method: 'POST', body: {} });
      tlLoad(false);
      T.data = res.state;
      render();
      await playBoss(res.battle);
    } catch (e) {
      toast(e.message);
    } finally {
      T.busy = false;
    }
  }

  async function retryFloor(floorId) {
    if (T.busy || T.autoRunning) return;
    T.busy = true;
    try {
      const res = await api('/api/tower/retry', { method: 'POST', body: { floor: floorId } });
      T.data = res.state;
      T.pos[floorId] = findChar(floorId, 'E');   // 回到本层入口重来
      render();
      toast('本层的怪物重新现身了');
      sfx.stairs();
    } catch (e) {
      toast(e.message);
    } finally {
      T.busy = false;
    }
  }

  /* ---------------------------------------------------------- 全自动闯关演示 */

  let aaStampToken = 0;

  function setAutoStage(text) {
    const el = $('#aa-stage-text');
    if (el) el.textContent = text;
  }

  function aaSetHeroHp(hp, max) {
    const pct = max > 0 ? Math.max(0, Math.min(100, (hp / max) * 100)) : 0;
    $('#aa-hero-hp').style.width = pct + '%';
    $('#aa-hero-hp-t').textContent = `${Math.max(0, Math.round(hp))} / ${Math.max(0, Math.round(max))}`;
    $('#aa-hero-side').classList.toggle('low', pct <= 25);
  }

  function aaSetHero(h) {
    if (!h) return;
    aaSetHeroHp(h.hp, h.hpMax);
    $('#aa-hero-sub').textContent = `Lv.${h.level} · ATK ${h.atk} · DEF ${h.def}`;
    const art = $('#aa-hero');
    const tier = heroTier(h.defeated || 0);
    if (art.dataset.tier !== String(tier)) {
      art.dataset.tier = String(tier);
      art.innerHTML = heroArt(h.defeated || 0);
    }
  }

  function aaSetFoeHp(hp, max) {
    const pct = max > 0 ? Math.max(0, Math.min(100, (hp / max) * 100)) : 0;
    $('#aa-foe-hp').style.width = pct + '%';
    $('#aa-foe-hp-t').textContent = `${Math.max(0, Math.round(hp))} / ${Math.max(0, Math.round(max))}`;
  }

  function aaSetFoeIdle() {
    $('#aa-foe-side').className = 'aa-fighter foe';
    $('#aa-foe').innerHTML = '<span class="aa-wait">?</span>';
    $('#aa-foe-name').textContent = '等待入场';
    $('#aa-foe-sub').textContent = '怪物会依次上场';
    $('#aa-foe-hp').style.width = '0%';
    $('#aa-foe-hp-t').textContent = '—';
  }

  function aaSetFoe(monster, hp, sub, boss, refId) {
    const side = $('#aa-foe-side');
    side.className = 'aa-fighter foe' + (boss ? ' boss' : '');
    $('#aa-foe').innerHTML = mobArt(refId, boss ? 'big' : '');
    $('#aa-foe-name').textContent = monster.name;
    $('#aa-foe-sub').textContent = sub || '';
    aaSetFoeHp(hp, hp);
    void side.offsetWidth;
    side.classList.add('enter');
    setTimeout(() => side.classList.remove('enter'), 520);
  }

  function aaFloat(side, text, cls) {
    const host = side === 'foe' ? $('#aa-foe-side') : $('#aa-hero-side');
    const n = document.createElement('span');
    n.className = 'dmg aa-dmg ' + (cls || '');
    n.textContent = text;
    host.appendChild(n);
    setTimeout(() => n.remove(), 950);
  }

  function aaSlash() {
    const s = document.createElement('div');
    s.className = 'slash';
    $('#aa-stage').appendChild(s);
    setTimeout(() => s.remove(), 420);
  }

  function aaShake() {
    const el = $('#aa-scene');
    el.classList.remove('shake');
    void el.offsetWidth;
    el.classList.add('shake');
  }

  function aaLog(html, cls = '') {
    const box = $('#aa-log');
    const line = document.createElement('div');
    line.className = 'b-line ' + cls;
    line.innerHTML = html;
    box.appendChild(line);
    while (box.childElementCount > 60) box.firstElementChild.remove();
    box.scrollTop = box.scrollHeight;
  }

  function aaStamp(title, sub, cls) {
    const el = $('#aa-stamp');
    const token = ++aaStampToken;
    el.hidden = true;
    el.className = 'aa-stamp ' + cls;
    el.innerHTML = `<b>${esc(title)}</b><span>${esc(sub)}</span>`;
    void el.offsetWidth;
    el.hidden = false;
    setTimeout(() => { if (token === aaStampToken) el.hidden = true; }, 1150);
  }

  function aaQueueFloor(f) {
    const levels = f.levels || [];
    $('#aa-queue').innerHTML = levels.map((lv) => `
      <div class="aq" data-lv="${esc(lv.id)}">
        <span class="aq-mini">${mobArt(lv.id)}</span>
        <i>${esc(lv.id)}</i>
        <b>${esc(lv.monster.name)}</b>
        <span class="aq-mark"></span>
      </div>`).join('');
    $('#aa-queue').scrollLeft = 0;
  }

  function aaQueueBoss(ev) {
    const q = $('#aa-queue');
    const el = document.createElement('div');
    el.className = 'aq boss active';
    el.dataset.lv = ev.id;
    el.innerHTML = `<span class="aq-mini">${mobArt(ev.id)}</span>
      <i>守卫</i><b>${esc(ev.monster.name)}</b><span class="aq-mark">▶</span>`;
    q.appendChild(el);
    q.scrollLeft = q.scrollWidth;
  }

  function aaMarkLevel(id, cls) {
    $$('#aa-queue .aq').forEach((el) => el.classList.remove('active'));
    const el = $(`#aa-queue .aq[data-lv="${CSS.escape(id)}"]`);
    if (!el) return;
    el.classList.remove('active', 'done', 'blocked');
    if (cls) el.classList.add(cls);
    const mark = el.querySelector('.aq-mark');
    if (mark) mark.textContent = cls === 'done' ? '✓' : cls === 'blocked' ? '×' : cls === 'active' ? '▶' : '';
  }

  function aaProgress(n, total) {
    const pct = total ? Math.min(100, (n / total) * 100) : 0;
    $('#aa-progress-bar').style.width = pct + '%';
    $('#aa-progress-t').textContent = `${n} / ${total}`;
  }

  /* 全塔挑战的楼层进度条：和结算页同款的 st-floor 卡片，逐场更新 */
  function aaSpineInit(preview) {
    const host = $('#aa-spine');
    if (!host) return;
    const rows = (preview.floors || []).map((f) => `
      <div class="st-floor" data-aa-floor="${f.id}">
        <span class="st-floor-name">0${f.no} ${esc(f.name)}</span>
        <span class="st-floor-bar"><i style="width:0%"></i></span>
        <b data-aa-n>0/${f.count || (f.levels || []).length}</b>
      </div>`);
    rows.push(`<div class="st-floor final" data-aa-floor="final">
      <span class="st-floor-name">05 塔顶</span>
      <span class="st-floor-bar"><i style="width:0%"></i></span>
      <b data-aa-n>0/1</b>
    </div>`);
    host.innerHTML = `<div class="st-floors">${rows.join('')}</div>`;
  }

  function aaSpineEl(fid) {
    return document.querySelector(`#aa-spine [data-aa-floor="${fid}"]`);
  }

  function aaSpineTick(fid, done, total) {
    const el = aaSpineEl(fid);
    if (!el) return;
    const bar = el.querySelector('.st-floor-bar i');
    const num = el.querySelector('[data-aa-n]');
    if (bar) bar.style.width = `${total ? Math.min(100, (done / total) * 100) : 0}%`;
    if (num) num.textContent = `${done}/${total}`;
  }

  function aaSpineMark(fid, cls) {
    const el = aaSpineEl(fid);
    if (!el) return;
    el.classList.remove('active', 'ok', 'fail');
    if (cls) el.classList.add(cls);
  }

  /* 战斗/推演加载遮罩：火把 + 文字，手动出招和全塔推演共用 */
  function tlLoad(show, text, sub) {
    const el = $('#tl-load');
    if (!el) return;
    if (text != null) {
      const t = $('#tl-load-text');
      if (t) t.innerHTML = `${esc(text)}<span class="tl-dots"><b>.</b><b>.</b><b>.</b></span>`;
    }
    const s = $('#tl-load-sub');
    if (s && sub != null) s.textContent = sub;
    el.hidden = !show;
  }

  async function aaShowIntro(kicker, name, sub, story, ms = 1250) {
    const intro = $('#aa-intro');
    $('#aa-intro-kicker').textContent = kicker;
    $('#aa-intro-name').textContent = name;
    $('#aa-intro-sub').textContent = sub || '';
    $('#aa-intro-story').textContent = story || '';
    intro.style.animationDuration = T.auto ? '.7s' : '1.15s';
    intro.hidden = true;
    intro.classList.remove('show');
    void intro.offsetWidth;
    intro.hidden = false;
    intro.classList.add('show');
    await sleep(ms);
    intro.hidden = true;
    intro.classList.remove('show');
  }

  async function aaIntroduceFloor(f) {
    $('#aa-barrier').hidden = true;
    $('#aa-hero-side').classList.remove('down', 'hit');
    $('#aa-floor').textContent = `第 ${f.no} 层 · ${f.name}`;
    $('#aa-floor-name').textContent = `第 ${f.no} 层 · ${f.name}`;
    $('#aa-floor-sub').textContent = f.subtitle || '';
    $('#aa-backno').textContent = String(f.no).padStart(2, '0');
    aaQueueFloor(f);
    aaProgress(0, f.count || (f.levels || []).length);
    aaSetFoeIdle();
    aaSetHero(f.start);
    setAutoStage(`第 ${f.no} 层 · ${f.name}`);
    sfx.stairs();
    await aaShowIntro(`第 ${f.no} 层`, f.name, f.subtitle, f.story);
  }

  async function aaCamp(ev, f) {
    aaSetHero(ev.hud);
    $('#aa-hero-side').classList.remove('down', 'hit');
    $('#aa-foe-side').className = 'aa-fighter foe';
    aaSetFoeIdle();
    aaLog(`第 ${f.no} 层入口 · 营地休整，生命回满${ev.heal ? `（+${ev.heal}）` : ''}。`, 'gold');
    aaStamp('营地', `生命回满 ${ev.hud.hp}`, 'ok');
    setAutoStage(`第 ${f.no} 层 · 营地休整`);
    sfx.levelup();
    await sleep(900);
  }

  async function aaStrike() {
    const foe = $('#aa-foe-side');
    const me = $('#aa-hero-side');
    me.classList.add('lunge');
    sfx.swing();
    await sleep(150);
    me.classList.remove('lunge');
    if (T.autoSkip) return;
    aaSlash();
    sfx.hit();
    await sleep(110);
    foe.classList.add('hit');
    aaShake();
    await sleep(260);
    foe.classList.remove('hit');
  }

  async function aaKill(ev) {
    const foe = $('#aa-foe-side');
    aaSetFoeHp(0, ev.monsterHp);
    aaFloat('foe', `-${ev.monsterHp}`, 'crit');
    burst(foe, ev.monster.tint);
    foe.classList.add('dead');
    sfx.kill();
    await sleep(420);
    aaLog(`<b class="ok">检测通过 · 击杀</b> ${esc(ev.title)}。${esc(ev.monster.name)} 消散了。`, 'ok');
    const gain = Math.max(0, ev.hpAfter - ev.hudBefore.hp);
    if (gain) {
      aaFloat('me', `+${gain}`, 'heal');
      aaLog(`拾起战利品，回复 <b class="gold">${gain}</b> 点生命。`, 'gold');
    }
    if (ev.exp) aaFloat('foe', `+${ev.exp} EXP`, 'exp');
    aaSetHero(ev.hud);
    if (ev.levelUp) {
      sfx.levelup();
      burst($('#aa-hero-side'), '#ffd66b');
      aaLog(`<b class="gold">升级！</b> 现在是 Lv.${ev.hud.level} ${esc(ev.hud.title)}。`, 'gold');
    }
    aaStamp('击杀', '检测通过', 'ok');
    await sleep(420);
  }

  async function aaBlocked(ev, f) {
    const foe = $('#aa-foe-side');
    aaSetFoeHp(ev.monsterHp, ev.monsterHp);
    foe.classList.add('shielded');
    aaFloat('foe', '0', 'block');
    aaLog(`剑刃劈在检测屏障上——<b class="bad">${esc(ev.title)} 没过，怪物打不动</b>。`, 'bad');
    if (ev.probe && ev.probe.value) aaLog(`这一项：${esc(ev.probe.value)}`, 'hint');
    aaStamp('打不动', '检测未通过', 'bad');
    sfx.seal();
    await sleep(650);
    if (T.autoSkip) return;

    const hits = ev.hits && ev.hits.length ? ev.hits : [ev.dmg];
    let hp = ev.hudBefore.hp;
    for (const d of hits) {
      if (T.autoSkip) return;
      aaLog(`<b>${esc(ev.monster.name)}</b> 反击。`, 'foe');
      foe.classList.add('counter');
      sfx.hurt();
      aaShake();
      await sleep(160);
      hp = Math.max(0, hp - d);
      aaSetHeroHp(hp, ev.hudBefore.hpMax);
      aaFloat('me', `-${d}`, 'hurt');
      $('#aa-hero-side').classList.add('hit');
      await sleep(310);
      foe.classList.remove('counter');
      $('#aa-hero-side').classList.remove('hit');
    }
    if (T.autoSkip) return;

    if (ev.dead) {
      aaLog('<b class="bad">你被打倒了，眼前一黑。</b>', 'bad');
      $('#aa-hero-side').classList.add('down');
      sfx.hurt();
      aaShake();
      await sleep(520);
    } else {
      aaLog(`你拖着 ${ev.hpAfter} 点血退了下来。`, 'hint');
      await sleep(220);
    }
    if (T.autoSkip) return;

    aaSetHero(ev.hud);
    aaMarkLevel(ev.id, 'blocked');
    const others = (f.levels || []).filter((x) => !x.ok && x.id !== ev.id);
    $('#aa-barrier-kicker').textContent = '检测屏障';
    $('#aa-barrier-verdict').textContent = '检测未通过 · 怪物打不动';
    $('#aa-barrier-value').textContent = ev.probe && ev.probe.value ? ev.probe.value : '这一项检测没有通过。';
    $('#aa-barrier-advice').textContent = ev.probe && ev.probe.advice ? ev.probe.advice : '修好这一项之后再来挑战。';
    const extra = $('#aa-barrier-extra');
    if (others.length) {
      extra.hidden = false;
      extra.textContent = `本层还有 ${others.length} 项没过：${others.map((x) => `${x.id} ${x.title}`).join('、')}。`;
    } else {
      extra.hidden = true;
      extra.textContent = '';
    }
    $('#aa-barrier').hidden = false;
    setAutoStage(`${ev.id} ${ev.title} 检测未通过 · 记下这处，挑战继续`);
    await sleep(1700);
  }

  async function aaFight(ev, f) {
    const p = ev.probe || {};
    $('#aa-barrier').hidden = true;
    $('#aa-hero-side').classList.remove('down', 'hit');
    aaSetHero(ev.hudBefore);
    if (ev.rescued) aaLog('营地把你从地上扶了起来，生命回满，继续挑战。', 'gold');
    aaSetFoe(ev.monster, ev.monsterHp, `${sevLabel(p.sev)} · 威压 ${ev.monsterAtk || 0}`, false, ev.id);
    aaMarkLevel(ev.id, 'active');
    setAutoStage(`第 ${f.no} 层 · ${ev.id} ${ev.title}`);
    aaLog(`<b>${esc(ev.monster.name)}</b> 从阴影里走了出来：<b>${esc(ev.title)}</b>。`);
    await sleep(430);
    if (T.autoSkip) return 'skip';
    await aaStrike();
    if (T.autoSkip) return 'skip';
    if (!ev.killed) {
      await aaBlocked(ev, f);
      return 'blocked';
    }
    await aaKill(ev);
    aaMarkLevel(ev.id, 'done');
    return 'done';
  }

  async function aaGear(ev, f) {
    const g = ev.gear;
    if (!g) return;
    aaSetHero(ev.hud);
    aaLog(`第 ${f.no} 层清空，宝箱打开：<b class="gold">${esc(g.name)}</b> · ${esc(g.label)} +${g.value}`, 'gold');
    sfx.levelup();
    const drop = $('#aa-drop');
    $('#aa-drop-name').textContent = g.name;
    $('#aa-drop-stat').textContent = `${g.label} +${g.value}`;
    drop.hidden = true;
    void drop.offsetWidth;
    drop.hidden = false;
    setAutoStage(`第 ${f.no} 层清空 · 获得 ${g.name}`);
    await sleep(1150);
    drop.hidden = true;
  }

  async function aaBoss(ev, f) {
    aaSetHero(ev.hudBefore);
    aaSetFoe(ev.monster, ev.monsterHp, '本层守卫 · 全部小关已清', true, ev.id);
    aaQueueBoss(ev);
    setAutoStage(`第 ${f.no} 层守卫 · ${ev.monster.name}`);
    aaLog(`<b class="gold">${esc(ev.monster.name)}</b> 站了起来，整层都在震动。`, 'gold');
    sfx.boss();
    await sleep(620);

    const rounds = 3;
    for (let i = 0; i < rounds; i++) {
      if (T.autoSkip) return;
      await aaStrike();
      if (T.autoSkip) return;
      const left = Math.round(ev.monsterHp * (1 - (i + 1) / rounds));
      aaSetFoeHp(left, ev.monsterHp);
      aaFloat('foe', `-${Math.round(ev.monsterHp / rounds)}`, 'crit');
      aaShake();
      await sleep(300);
    }
    const foe = $('#aa-foe-side');
    aaSetFoeHp(0, ev.monsterHp);
    burst(foe, ev.monster.tint);
    burst(foe, '#ffd66b');
    foe.classList.add('dead');
    sfx.kill();
    await sleep(520);
    aaLog(`<b class="ok">${esc(ev.monster.name)} 倒下了。</b>第 ${f.no} 层守卫清除。`, 'ok');
    const gain = Math.max(0, ev.hpAfter - ev.hpBefore);
    if (gain) {
      aaFloat('me', `+${gain}`, 'heal');
      aaLog(`守卫的补给让生命回到 ${ev.hpAfter}。`, 'gold');
    }
    if (ev.exp) aaFloat('foe', `+${ev.exp} EXP`, 'exp');
    aaSetHero(ev.hud);
    if (ev.levelUp) {
      sfx.levelup();
      burst($('#aa-hero-side'), '#ffd66b');
      aaLog(`<b class="gold">升级！</b> 现在是 Lv.${ev.hud.level} ${esc(ev.hud.title)}。`, 'gold');
    }
    const chip = $(`#aa-queue .aq[data-lv="${CSS.escape(ev.id)}"]`);
    if (chip) {
      chip.classList.remove('active');
      chip.classList.add('done');
      const mark = chip.querySelector('.aq-mark');
      if (mark) mark.textContent = '✓';
    }
    aaStamp('层通', `第 ${f.no} 层守卫倒下`, 'ok');
    await sleep(520);
  }

  async function aaBossSeal(ev, f) {
    aaSetHero(ev.hud);
    $('#aa-hero-side').classList.remove('down', 'hit');
    aaSetFoe(ev.monster, ev.monsterHp, `层主 · 本层还有 ${ev.failed.length} 项未通过`, true, ev.id);
    $('#aa-foe-side').classList.add('shielded');
    aaQueueBoss(ev);
    aaLog(`<b class="bad">${esc(ev.monster.name)} 被本层未通过的检测封印着，无法挑战。</b>`, 'bad');
    aaStamp('封印', `第 ${f.no} 层 · 层主未解封`, 'bad');
    setAutoStage(`第 ${f.no} 层守卫 · 封印中`);
    sfx.seal();
    await sleep(520);

    const names = (f.levels || [])
      .filter((lv) => (ev.failed || []).includes(lv.id))
      .map((lv) => `${lv.id} ${lv.title}`);
    $('#aa-barrier-kicker').textContent = '层主封印';
    $('#aa-barrier-verdict').textContent = '本层未清空 · 层主无法挑战';
    $('#aa-barrier-value').textContent = `还有 ${names.length} 项检测没通过：${names.join('、')}。`;
    $('#aa-barrier-advice').textContent = ev.probe && ev.probe.advice ? ev.probe.advice : '把本层每一关都打通，层主才会解封。';
    $('#aa-barrier-extra').hidden = true;
    $('#aa-barrier').hidden = false;
    await sleep(1700);

    const chip = $(`#aa-queue .aq[data-lv="${CSS.escape(ev.id)}"]`);
    if (chip) {
      chip.classList.remove('active');
      chip.classList.add('blocked');
      const mark = chip.querySelector('.aq-mark');
      if (mark) mark.textContent = '×';
    }
  }

  async function aaFinalSeal(ev) {
    $('#aa-floor').textContent = '塔顶 · 最终 BOSS';
    $('#aa-floor-name').textContent = '塔顶';
    $('#aa-floor-sub').textContent = '封印未解';
    $('#aa-backno').textContent = '05';
    $('#aa-queue').innerHTML = `
      <div class="aq boss active" data-lv="${esc(ev.id)}">
        <span class="aq-mini">${mobArt(ev.id)}</span>
        <i>塔主</i><b>${esc(ev.monster.name)}</b><span class="aq-mark">▶</span>
      </div>`;
    $('#aa-progress-bar').style.width = '100%';
    $('#aa-progress-t').textContent = '塔顶';
    aaSetHero(ev.hud);
    aaSetFoe(ev.monster, ev.monsterHp, '塔主 · 封印未解', true, ev.id);
    $('#aa-foe-side').classList.add('shielded');
    setAutoStage('塔顶 · Claude 仍在封印之后');
    aaLog('<b class="bad">四层没有全部清空，塔顶的封印还在，塔主无法挑战。</b>', 'bad');
    aaStamp('封印', '四层未全部清空', 'bad');
    sfx.seal();
    await sleep(620);

    const floors = ev.failedFloors || [];
    $('#aa-barrier-kicker').textContent = '塔顶封印';
    $('#aa-barrier-verdict').textContent = '四层未全部清空 · 塔主仍在封印之后';
    $('#aa-barrier-value').textContent = floors
      .map((x) => `第 ${x.no} 层还有 ${x.failed.length} 项没过（${x.failed.join('、')}）`)
      .join('；') + '。';
    $('#aa-barrier-advice').textContent = ev.probe && ev.probe.advice ? ev.probe.advice : '把四层的层主都打倒，才能挑战 Claude。';
    $('#aa-barrier-extra').hidden = true;
    $('#aa-barrier').hidden = false;
    await sleep(1700);
  }

  async function aaFinal(ev) {
    $('#aa-barrier').hidden = true;
    $('#aa-hero-side').classList.remove('down', 'hit');
    $('#aa-floor').textContent = '塔顶 · 最终 BOSS';
    $('#aa-floor-name').textContent = '塔顶';
    $('#aa-floor-sub').textContent = '封印解除';
    $('#aa-backno').textContent = '05';
    $('#aa-queue').innerHTML = `
      <div class="aq boss active" data-lv="${esc(ev.id)}">
        <span class="aq-mini">${mobArt(ev.id)}</span>
        <i>塔主</i><b>${esc(ev.monster.name)}</b><span class="aq-mark">▶</span>
      </div>`;
    $('#aa-progress-bar').style.width = '100%';
    $('#aa-progress-t').textContent = '塔顶';
    aaSetFoeIdle();
    setAutoStage('塔顶 · 最终决战');
    sfx.stairs();
    await aaShowIntro('第 5 层', '塔顶', '封印解除', '四层守卫全部倒下，塔顶的灯亮着最后一盏。');
    if (T.autoSkip) return;

    aaSetHero(ev.hudBefore);
    aaSetFoe(ev.monster, ev.monsterHp, '塔主 · 最终 BOSS', true, ev.id);
    setAutoStage('塔顶 · Claude 现身');
    aaLog(`<b class="gold">${esc(ev.monster.name)}</b> 从王座上站了起来。`, 'gold');
    sfx.boss();
    await sleep(720);

    const rounds = 4;
    for (let i = 0; i < rounds; i++) {
      if (T.autoSkip) return;
      await aaStrike();
      if (T.autoSkip) return;
      const left = Math.round(ev.monsterHp * (1 - (i + 1) / rounds));
      aaSetFoeHp(left, ev.monsterHp);
      aaFloat('foe', `-${Math.round(ev.monsterHp / rounds)}`, 'crit');
      aaShake();
      await sleep(340);
    }
    const foe = $('#aa-foe-side');
    aaSetFoeHp(0, ev.monsterHp);
    burst(foe, ev.monster.tint);
    burst(foe, '#ffd66b');
    foe.classList.add('dead');
    sfx.win();
    await sleep(620);
    aaLog(`<b class="ok">${esc(ev.monster.name)} 倒下了。</b>塔顶的灯灭了。`, 'ok');
    // 塔顶崩解：真正的通关时刻，全屏演出（可跳过；整局只播一次）
    if (!T.autoSkip) await playFinisher();
    if (ev.exp) aaFloat('foe', `+${ev.exp} EXP`, 'exp');
    aaSetHero(ev.hud);
    if (ev.levelUp) {
      sfx.levelup();
      burst($('#aa-hero-side'), '#ffd66b');
      aaLog(`<b class="gold">升级！</b> 现在是 Lv.${ev.hud.level} ${esc(ev.hud.title)}。`, 'gold');
    }
    const chip = $(`#aa-queue .aq[data-lv="${CSS.escape(ev.id)}"]`);
    if (chip) {
      chip.classList.remove('active');
      chip.classList.add('done');
      const mark = chip.querySelector('.aq-mark');
      if (mark) mark.textContent = '✓';
    }
    aaStamp('通关', '魔塔试炼 · 完成', 'ok');
    setAutoStage('塔顶 · 魔塔通关');
    await sleep(900);
  }

  function aaResetArena() {
    $('#aa-log').innerHTML = '';
    $('#aa-queue').innerHTML = '';
    $('#aa-hero').innerHTML = '';
    delete $('#aa-hero').dataset.tier;
    $('#aa-hero-side').className = 'aa-fighter me';
    aaSetFoeIdle();
    $('#aa-hero-hp').style.width = '0%';
    $('#aa-hero-hp-t').textContent = '— / —';
    $('#aa-hero-sub').textContent = '—';
    $('#aa-progress-bar').style.width = '0%';
    $('#aa-progress-t').textContent = '—';
    $('#aa-stamp').hidden = true;
    $('#aa-drop').hidden = true;
    $('#aa-intro').hidden = true;
    $('#aa-intro').classList.remove('show');
    $('#aa-barrier').hidden = true;
    $('#aa-floor').textContent = '准备中';
    $('#aa-floor-name').textContent = '魔塔';
    $('#aa-floor-sub').textContent = '自动推演';
    $('#aa-backno').textContent = '00';
    $('#aa-scene').classList.remove('shake');
  }

  /* ---------------------------------------------------------- 结算页 / 挑战历史 */

  function fmtNow() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  function currentLevelMap() {
    const map = new Map();
    ((T.data && T.data.floors) || []).forEach((f) => (f.levels || []).forEach((lv) => map.set(lv.id, lv)));
    return map;
  }

  function fixableNowSet() {
    const scan = window.CC.state.scan;
    return new Set(((scan && scan.items) || [])
      .filter((i) => i.fix && i.fix.kind !== 'manual')
      .map((i) => i.id));
  }

  function previewToSettle(preview, skipped) {
    const s = (preview && preview.summary) || {};
    const failed = s.failedDetail || [];
    return {
      live: true,
      recorded: false,
      skipped: !!skipped,
      at: fmtNow(),
      id: null,
      no: null,
      cleared: !!s.cleared,
      defeated: s.defeated || 0,
      total: s.total || 19,
      deaths: s.deaths || 0,
      clearedFloors: s.clearedFloors || 0,
      bosses: s.bosses || 0,
      failedCount: failed.length,
      failed,
      gear: s.gear || [],
      floors: s.floorResults || [],
    };
  }

  function recordToSettle(rec) {
    return {
      live: false,
      recorded: true,
      skipped: !!rec.skipped,
      at: rec.at || '',
      id: rec.id || null,
      no: rec.no || null,
      ts: rec.ts || 0,
      cleared: !!rec.cleared,
      defeated: rec.defeated || 0,
      total: rec.total || 19,
      deaths: rec.deaths || 0,
      clearedFloors: rec.clearedFloors || 0,
      bosses: rec.bosses || 0,
      failedCount: rec.failedCount == null ? (rec.failed || []).length : rec.failedCount,
      failed: rec.failed || [],
      gear: rec.gear || [],
      floors: rec.floors || [],
    };
  }

  function settleIssues() {
    if (!T.settle) return [];
    const cur = currentLevelMap();
    const fixable = fixableNowSet();
    const scanItems = new Map(((window.CC.state.scan && window.CC.state.scan.items) || []).map((i) => [i.id, i]));
    return (T.settle.failed || []).map((x) => {
      const lv = cur.get(x.id);
      const done = !!(lv && lv.ok);
      const fixIds = done ? [] : (x.fixIds || []).filter((id) => fixable.has(id));
      const fixItems = fixIds.map((id) => ({ id, title: (scanItems.get(id) || {}).title || id }));
      const target = !done && !fixIds.length
        ? (x.id === '4-1' ? 'isolation' : '')
        : '';
      return { ...x, done, fixIds, fixItems, target };
    });
  }

  function settleFixIds() {
    return settleIssues().flatMap((x) => x.fixIds);
  }

  function updateSettleSelUI() {
    const issues = settleIssues();
    const byId = new Map(issues.map((x) => [x.id, x]));
    let items = 0;
    T.settleSel.forEach((id) => { items += ((byId.get(id) || {}).fixIds || []).length; });
    const btn = $('#st-fix-sel');
    if (btn) {
      btn.disabled = items === 0;
      btn.textContent = `修复选中（${items}）`;
    }
    const note = $('#st-sel-note');
    if (note) {
      note.textContent = T.settleSel.size
        ? `已选 ${T.settleSel.size} 处 · ${items} 个可自动清理项`
        : `可自动清理 ${issues.reduce((n, x) => n + x.fixIds.length, 0)} 项`;
    }
  }

  function renderSettle() {
    const body = $('#settle-body');
    if (!body) return;
    const st = T.settle;
    if (!st) {
      $('#settle-sub').textContent = '还没有挑战结算。先在魔塔里走完全塔，结果会在这里展开。';
      body.innerHTML = `<div class="empty st-empty">
        <svg><use href="#i-tower"/></svg>
        <p>走一遍全塔，看看哪几只怪物打不动。</p>
        <button class="btn primary" data-settle-action="run">开始全塔挑战</button>
      </div>`;
      return;
    }

    const issues = settleIssues();
    const valid = new Set(issues.filter((x) => x.fixIds.length).map((x) => x.id));
    T.settleSel = new Set([...T.settleSel].filter((id) => valid.has(id)));
    const allFix = settleFixIds();
    const fixIssues = issues.filter((x) => x.fixIds.length).length;
    const meta = [
      st.no ? `第 ${st.no} 次挑战` : '本次挑战',
      st.at || '',
      st.skipped ? '跳过演出' : '完整演出',
      st.recorded === false ? '正在记入挑战历史' : '已记入挑战历史',
    ].filter(Boolean).join(' · ');
    $('#settle-sub').textContent = meta;
    const sevDone = issues.filter((x) => x.done).length;
    const floorRows = (st.floors || []).map((f) => {
      const pct = f.count ? Math.max(0, Math.min(100, (f.defeated / f.count) * 100)) : 0;
      return `<div class="st-floor ${f.cleared ? 'ok' : ''}">
        <span class="st-floor-name">0${f.no} ${esc(f.name)}</span>
        <span class="st-floor-bar"><i style="width:${pct}%"></i></span>
        <b>${f.defeated}/${f.count}</b>
      </div>`;
    });
    if (floorRows.length) {
      floorRows.push(`<div class="st-floor final ${st.cleared ? 'ok' : ''}">
        <span class="st-floor-name">05 塔顶</span>
        <span class="st-floor-bar"><i style="width:${st.cleared ? 100 : 0}%"></i></span>
        <b>${st.cleared ? 1 : 0}/1</b>
      </div>`);
    }

    const gear = (st.gear || []).map((g) => `<span><b>${esc(g.name)}</b> ${esc(g.label)} +${g.value}</span>`).join('');
    const issueHtml = issues.length ? issues.map((x) => {
      const checked = T.settleSel.has(x.id);
      let howArr = Array.isArray(x.how) ? x.how : (x.how ? [x.how] : []);
      if (typeof x.how === 'string' && x.how.startsWith('[')) {
        try { howArr = JSON.parse(x.how.replace(/'/g, '"')); } catch (_) {}
      }
      const how = howArr.join(' · ');
      const fixNames = x.fixItems.map((f) => `<em title="${esc(f.id)}">${esc(f.title)}</em>`).join('');
      return `<article class="st-issue${x.done ? ' done' : ''}">
        <div class="st-check">${x.done
          ? '<span class="st-check-done">✓</span>'
          : x.fixIds.length
            ? `<label><input type="checkbox" data-settle-check="${esc(x.id)}"${checked ? ' checked' : ''}><span></span></label>`
            : '<span class="st-check-manual">手</span>'}</div>
        <div class="st-issue-main">
          <div class="st-issue-head">
            <span class="br-sev s-${esc(x.sev || 'info')}">${sevLabel(x.sev)}</span>
            <b>${esc(x.id)} ${esc(x.title)}</b>
            ${x.done ? '<span class="st-done">已修复</span>' : ''}
          </div>
          <i class="st-meta">第 ${esc(x.floorNo)} 层 · ${esc(x.floorName || '')} · ${esc(x.monster ? x.monster.name : '')}</i>
          <p class="st-value">${esc(x.value || '')}</p>
          ${x.advice || x.detail ? `<p class="st-advice">${esc(x.advice || x.detail)}</p>` : ''}
          ${how ? `<p class="st-how">${esc(how)}</p>` : ''}
          <div class="st-issue-foot">
            <div class="st-fix-names">${fixNames}</div>
            <div class="st-issue-acts">
              ${x.fixIds.length ? `<button class="st-link" data-settle-action="fix-one" data-ids="${esc(x.fixIds.join(','))}">${x.fixIds.length > 1 ? `清理这组 ${x.fixIds.length} 项` : '直接清理'}</button>` : ''}
              ${!x.done && x.act && x.act.kind === 'open' ? `<button class="st-link" data-settle-action="open" data-pane="${esc(x.act.pane || 'general')}">${esc(x.act.label || '打开对应设置')}</button>` : ''}
              ${!x.done && x.act && x.act.kind === 'profile' ? `<button class="st-link" data-settle-action="profile">${esc(x.act.label || '一键建隔离配置档')}</button>` : ''}
              ${!x.done && x.act && x.act.kind === 'tour' ? `<button class="st-link" data-settle-action="tour">${esc(x.act.label || '开始全塔挑战')}</button>` : ''}
              ${!x.done && x.act && x.act.kind === 'site' ? `<button class="st-link" data-settle-action="site">${esc(x.act.label || '打开检测网站')}</button>` : ''}
              ${!x.done && x.act && x.act.kind === 'goto' ? `<button class="st-link" data-settle-action="goto" data-tab="${esc(x.act.tab || 'findings')}" data-focus="${esc(x.act.focus || '')}">${esc(x.act.label || '去处理')}</button>` : ''}
              ${!x.done && x.act && x.act.kind === 'openfile' ? `<button class="st-link" data-settle-action="openfile" data-file="${esc(x.act.file || '')}">${esc(x.act.label || '打开文件')}</button>` : ''}
              ${!x.done && x.act && x.act.kind === 'probe' ? `<button class="st-link" data-settle-action="probe">${esc(x.act.label || '在本机浏览器里实测')}</button>` : ''}
              ${x.target === 'isolation' ? '<button class="st-link" data-settle-action="goto" data-tab="isolation">去建隔离配置档</button>' : ''}
              ${!x.done && !x.fixIds.length && !x.target && !x.act ? '<span class="st-manual-tip">按建议手动处理</span>' : ''}
            </div>
          </div>
        </div>
      </article>`;
    }).join('') : `<div class="st-clear">
      <b>全塔没有拦路的检测</b>
      <p>${st.total} 只检测怪物全部通过，塔主也已解封。修掉的问题会在这里消失。</p>
    </div>`;

    body.innerHTML = `
      <div class="st-hero ${st.cleared ? 'ok' : 'bad'}">
        <div class="st-hero-main">
          <div class="st-kicker">TOUR ${st.no ? '#' + st.no : '· 当前'} <span>${st.recorded === false ? '记录中…' : '已归档'}</span></div>
          <h2>${st.cleared ? '勇者走完了整座塔' : `${issues.filter((x) => !x.done).length} 项检测把勇者挡在塔下`}</h2>
          <p>${st.cleared
            ? `全部 ${st.total} 项检测通过，四层与塔顶才全部亮灯。这一趟只读检测，没有改动真实闯关进度。`
            : `勇者一次走完全部 ${st.total} 只怪物。没通过的检测打不动，怪物也不会倒下；没通过的层主与塔主保持封印。`}</p>
          <div class="st-hero-acts">
            ${allFix.length ? `<button class="btn primary" data-settle-action="fix-all">修复全部可清理项（${allFix.length}）</button>` : ''}
            ${st.id ? `<button class="btn" data-settle-export="${esc(st.id)}">导出本次战报</button>` : ''}
            <button class="btn" data-settle-action="run">再挑战一次</button>
          </div>
        </div>
        <div class="st-portrait" aria-hidden="true">${heroArt(st.defeated)}</div>
      </div>

      <div class="st-stats">
        <div><b>${st.defeated}<small>/${st.total}</small></b><span>击杀</span></div>
        <div><b>${st.clearedFloors}<small>/4</small></b><span>通关楼层</span></div>
        <div><b>${st.bosses}<small>/4</small></b><span>层主</span></div>
        <div><b>${st.deaths}</b><span>阵亡</span></div>
        <div><b>${issues.filter((x) => !x.done).length}</b><span>仍未通过</span></div>
      </div>

      ${floorRows.length ? `<div class="st-floors">${floorRows.join('')}</div>` : ''}
      ${gear ? `<div class="st-gear">${gear}</div>` : ''}

      <div class="st-issues">
        <div class="st-issues-head">
          <div class="st-issues-title">
            <b>${issues.length ? '本次挑战记下的问题' : '检测清单'}</b>
            <i id="st-sel-note">可自动清理 ${allFix.length} 项</i>
          </div>
          <div class="st-issues-tools">
            ${fixIssues ? '<button class="btn sm" data-settle-action="select-all">全选可修复</button>' : ''}
            ${fixIssues ? '<button class="btn sm" data-settle-action="clear-sel">清空</button>' : ''}
            <button class="btn sm primary" id="st-fix-sel" data-settle-action="fix-selected" disabled>修复选中（0）</button>
          </div>
        </div>
        ${sevDone ? `<p class="st-fixed-note">${sevDone} 项已经消失，剩下的按建议处理后再挑战一次。</p>` : ''}
        <div class="st-grid">${issueHtml}</div>
        <p class="st-note">结算是一次只读挑战的快照；真实闯关进度、阵亡记录与装备都没有被改写。修复需预览确认；缓存、诊断日志和凭据不留副本，不可还原。</p>
      </div>`;
    updateSettleSelUI();
  }

  async function refreshSettle() {
    if (!T.settle) {
      try {
        if (!T.history) T.history = await api('/api/tower/history');
        const rec = (T.history.tours || [])[0];
        if (rec) T.settle = recordToSettle(rec);
      } catch (_) {}
    }
    renderSettle();
  }

  function renderCruise() {
    const body = $('#cruise-body');
    if (!body) return;
    const data = T.history;
    if (!data) {
      $('#cruise-sub').textContent = '每一次全塔挑战的结果与差距。挑战只读检测，不改动真实闯关进度。';
      body.innerHTML = `<div class="empty"><span class="loading-ring"></span><p>正在翻阅挑战历史…</p></div>`;
      return;
    }
    const tours = data.tours || [];
    $('#cruise-sub').textContent = tours.length
      ? `共 ${data.count} 次挑战 · 保留最近 ${tours.length} 次 · 只读检测，不改动真实闯关进度`
      : '每一次全塔挑战的结果与差距。挑战只读检测，不改动真实闯关进度。';
    if (!tours.length) {
      body.innerHTML = `<div class="empty cr-empty">
        <svg><use href="#i-tower"/></svg>
        <p>挑战历史还是空的。第一次挑战之后，每次结果都会留在这里。</p>
        <button class="btn primary" data-cruise-action="run">开始第一次挑战</button>
      </div>`;
      return;
    }
    const latest = tours[0];
    const prev = tours[1];
    let trend = '首次挑战';
    if (prev) {
      const d = latest.failedCount - prev.failedCount;
      trend = d < 0 ? `比上次少 ${-d} 项` : d > 0 ? `比上次多 ${d} 项` : '与上次持平';
    }
    body.innerHTML = `
      <div class="cr-stats">
        <div><b>${data.count}</b><span>挑战次数</span></div>
        <div><b>${latest.failedCount}</b><span>最近未通过</span></div>
        <div><b>${latest.deaths}</b><span>最近阵亡</span></div>
        <div><b>${latest.clearedFloors}<small>/4</small></b><span>最近通关楼层</span></div>
        <div class="trend ${latest.failedCount < (prev ? prev.failedCount : latest.failedCount + 1) ? 'good' : ''}"><b>${esc(trend)}</b><span>最近变化</span></div>
      </div>
      <div class="cr-list">${tours.map((r, i) => {
        const older = tours[i + 1];
        let delta = '';
        let dcls = '';
        if (older) {
          const d = r.failedCount - older.failedCount;
          if (d < 0) { delta = `少 ${-d} 项`; dcls = 'good'; }
          else if (d > 0) { delta = `多 ${d} 项`; dcls = 'bad'; }
          else { delta = '持平'; }
        }
        const fr = [
          ...(r.floors || []).map((f) => `<span class="${f.cleared ? 'ok' : ''}" title="${esc(f.name)}">${esc(f.id)} ${f.defeated}/${f.count}</span>`),
          `<span class="${r.cleared ? 'ok' : ''}" title="塔顶">f5 ${r.cleared ? 1 : 0}/1</span>`,
        ].join('');
        // 与上一条记录的结构化 diff：新增了哪些没过项、修掉了哪些
        let diffLine = '';
        if (older) {
          const curIds = new Set((r.failed || []).map((x) => x.id));
          const prevIds = new Set((older.failed || []).map((x) => x.id));
          const added = [...curIds].filter((x) => !prevIds.has(x));
          const fixed = [...prevIds].filter((x) => !curIds.has(x));
          const chips = [];
          if (added.length) chips.push(`<span class="cr-diff bad">新增 ${added.map(esc).join('、')}</span>`);
          if (fixed.length) chips.push(`<span class="cr-diff good">修复 ${fixed.map(esc).join('、')}</span>`);
          if (chips.length) diffLine = `<div class="cr-diff-row">${chips.join('')}</div>`;
        }
        const fails = (r.failed || []).map((x) => `<div class="cr-fail">
          <span class="br-sev s-${esc(x.sev || 'info')}">${sevLabel(x.sev)}</span>
          <div><b>${esc(x.id)} ${esc(x.title)}</b><i>第 ${esc(x.floorNo)} 层 · ${esc(x.monster ? x.monster.name : '')}</i><p>${esc(x.advice || x.value || x.detail || '')}</p></div>
        </div>`).join('');
        return `<details class="cr-item ${r.cleared ? 'ok' : ''}">
          <summary>
            <span class="cr-no">#${r.no || (tours.length - i)}</span>
            <span class="cr-main"><b>${r.cleared ? '全塔通关' : `${r.failedCount} 项没通过`}</b>
              <i>${esc(r.at || '')}${r.skipped ? ' · 跳过演出' : ''}</i></span>
            <span class="cr-nums"><b>${r.defeated}/${r.total}</b> 击杀 · <b>${r.deaths}</b> 阵亡</span>
            ${delta ? `<span class="cr-delta ${dcls}">${delta}</span>` : ''}
            <span class="cr-chev">›</span>
          </summary>
          <div class="cr-detail">
            ${fr ? `<div class="cr-floors">${fr}</div>` : ''}
            ${diffLine}
            ${fails ? `<div class="cr-fails">${fails}</div>` : '<p class="cr-ok">全部检测通过，塔顶的灯灭了。</p>'}
            <div class="cr-detail-foot">
              <span>真实闯关进度未被改动</span>
              <button class="st-link" data-cruise-export="${esc(r.id)}">导出战报</button>
              <button class="st-link" data-cruise-record="${esc(r.id)}">在结算页打开</button>
            </div>
          </div>
        </details>`;
      }).join('')}</div>`;
  }

  async function refreshCruise(force = true) {
    if (T.historyLoading) return;
    if (!T.history || force) {
      T.historyLoading = true;
      renderCruise();
      try {
        T.history = await api('/api/tower/history');
      } catch (e) {
        toast(e.message || '读取挑战历史失败');
      } finally {
        T.historyLoading = false;
      }
    }
    renderCruise();
  }

  function openSettleClean(ids) {
    if (!window.CC.selectForClean) {
      toast('清理入口还没准备好');
      return;
    }
    const n = window.CC.selectForClean(ids);
    if (!n) toast('这些项目没有可自动清理的项，请按建议手动处理');
  }

  function handleSettleAction(el) {
    const act = el.dataset.settleAction;
    if (act === 'run') { autoRun(); return; }
    if (act === 'fix-all') { openSettleClean(settleFixIds()); return; }
    if (act === 'select-all') {
      T.settleSel = new Set(settleIssues().filter((x) => x.fixIds.length).map((x) => x.id));
      renderSettle();
      return;
    }
    if (act === 'clear-sel') { T.settleSel.clear(); renderSettle(); return; }
    if (act === 'fix-selected') {
      const byId = new Map(settleIssues().map((x) => [x.id, x]));
      const ids = [...T.settleSel].flatMap((id) => ((byId.get(id) || {}).fixIds || []));
      openSettleClean(ids);
      return;
    }
    if (act === 'fix-one') { openSettleClean((el.dataset.ids || '').split(',').filter(Boolean)); return; }
    if (act === 'open') {
      api('/api/open', { method: 'POST', body: { pane: el.dataset.pane } })
        .then(() => toast('已在系统设置里打开对应面板'))
        .catch((e) => toast(e.message));
      return;
    }
    if (act === 'profile') { quickProfile(); return; }
    if (act === 'tour') { autoRun(); return; }
    if (act === 'site') {
      api('/api/open', { method: 'POST', body: { url: 'https://ip.net.coffee/claude/' } })
        .then(() => toast('已在浏览器打开检测网站'))
        .catch((e) => toast(e.message));
      return;
    }
    if (act === 'openfile') {
      api('/api/open', { method: 'POST', body: { file: el.dataset.file } })
        .then(() => toast('已用文本编辑打开文件'))
        .catch((e) => toast(e.message));
      return;
    }
    if (act === 'probe') {
      if (window.CC && window.CC.runWebrtcProbe) window.CC.runWebrtcProbe();
      else toast('页面还没准备好，刷新后再试');
      return;
    }
    if (act === 'goto') { jumpToAct(el.dataset.tab, el.dataset.focus); }
  }

  const QUICK_TZ = {
    'united states': 'America/New_York', '美国': 'America/New_York',
    'canada': 'America/Toronto', '加拿大': 'America/Toronto',
    'japan': 'Asia/Tokyo', '日本': 'Asia/Tokyo', 'korea': 'Asia/Tokyo', '韩国': 'Asia/Tokyo',
    'singapore': 'Asia/Singapore', '新加坡': 'Asia/Singapore',
    'hong kong': 'Asia/Hong_Kong', '香港': 'Asia/Hong_Kong', 'taiwan': 'Asia/Taipei', '台湾': 'Asia/Taipei',
    'united kingdom': 'Europe/London', '英国': 'Europe/London',
    'germany': 'Europe/Berlin', '德国': 'Europe/Berlin', 'france': 'Europe/Berlin', '法国': 'Europe/Berlin',
    'netherlands': 'Europe/Berlin', '荷兰': 'Europe/Berlin',
    'australia': 'Australia/Sydney', '澳大利亚': 'Australia/Sydney',
  };

  async function quickProfile() {
    const scan = (window.CC && window.CC.state && window.CC.state.scan) || {};
    const country = String((scan.network || {}).country || '').toLowerCase();
    const tz = QUICK_TZ[country] || 'UTC';
    try {
      const cur = await api('/api/profiles');
      const name = `隔离档-${(cur.profiles || []).length + 1}`;
      await api('/api/profiles', { method: 'POST', body: { name, tz } });
      toast(`已建配置档「${name}」（时区 ${tz}），可去「分身术」查看启动方式`, 4600);
      load(true);
    } catch (e) {
      toast(e.message || '建档失败');
    }
  }

  $('#settle-body').addEventListener('click', (e) => {
    const exEl = e.target.closest('[data-settle-export]');
    if (exEl) { exportTour(exEl.dataset.settleExport); return; }
    const actEl = e.target.closest('[data-settle-action]');
    if (actEl) handleSettleAction(actEl);
  });
  $('#settle-body').addEventListener('change', (e) => {
    const cb = e.target.closest('[data-settle-check]');
    if (!cb) return;
    if (cb.checked) T.settleSel.add(cb.dataset.settleCheck);
    else T.settleSel.delete(cb.dataset.settleCheck);
    updateSettleSelUI();
  });
  $('#settle-rerun').addEventListener('click', () => autoRun());
  $('#settle-cruise').addEventListener('click', () => switchTab('cruise'));
  $('#cruise-settle').addEventListener('click', () => switchTab('settle'));
  $('#cruise-body').addEventListener('click', (e) => {
    if (e.target.closest('[data-cruise-action="run"]')) { autoRun(); return; }
    const ex = e.target.closest('[data-cruise-export]');
    if (ex) { exportTour(ex.dataset.cruiseExport); return; }
    const btn = e.target.closest('[data-cruise-record]');
    if (!btn) return;
    const rec = ((T.history && T.history.tours) || []).find((x) => x.id === btn.dataset.cruiseRecord);
    if (!rec) return;
    T.settle = recordToSettle(rec);
    T.settleSel = new Set();
    switchTab('settle');
    renderSettle();
  });

  async function exportTour(id) {
    if (!id) { toast('这条记录还没有归档，挑战结束后自动写入挑战历史'); return; }
    try {
      const res = await api('/api/tower/tour-report', { method: 'POST', body: { id } });
      toast(`战报已导出：${res.path}`, 4200);
    } catch (e) {
      toast(e.message || '导出失败');
    }
  }

  async function finishTour(preview, skipped) {
    T.tourBusy = true;
    T.settle = previewToSettle(preview, skipped);
    T.settleSel = new Set();
    switchTab('settle');
    renderSettle();
    document.body.classList.remove('battling');
    try {
      const res = await api('/api/tower/history', {
        method: 'POST',
        body: { summary: preview.summary || {}, skipped },
      });
      Object.assign(T.settle, {
        id: res.record.id, no: res.record.no, ts: res.record.ts,
        at: res.record.at, recorded: true,
      });
      T.history = { count: res.count, kept: res.kept, tours: res.tours };
      if (T.data) {
        T.data.tour = { count: res.count, kept: res.kept, last: res.record, firstRun: false };
        T.data.unlocked = true;
        window.CC.setUnlocked(true);
      }
    } catch (e) {
      toast('挑战历史写入失败：' + e.message, 4200);
      if (T.data) {
        T.data.tour = { ...(T.data.tour || {}), firstRun: false };
        T.data.unlocked = true;
        window.CC.setUnlocked(true);
      }
    } finally {
      T.tourBusy = false;
      renderSettle();
      if ($('#panel-cruise') && $('#panel-cruise').classList.contains('active')) renderCruise();
    }
  }

  async function autoRun() {
    if (T.autoRunning || T.busy || T.tourBusy) return { ok: false };
    if (!T.data) {
      await load(false);
      if (!T.data) return { ok: false };
    }
    if (battleOpen) return { ok: false };

    let preview = null;
    let skipped = false;
    try {
      hideTitle();
      $('#victory').hidden = true;
      switchTab('tower');

      T.autoRunning = true;
      T.auto = true;
      T.autoSkip = false;
      T.busy = true;
      document.body.classList.add('battling');
      document.body.classList.add('auto-running');
      aaResetArena();
      $('#auto-arena').hidden = false;

      const skipBtn = $('#auto-skip');
      skipBtn.disabled = false;
      skipBtn.textContent = '跳过演出';
      setAutoStage('正在推演整座塔…');
      sfx.confirm();

      const totalLevels = ((T.data && T.data.floors) || []).reduce((n, f) => n + (f.count || 0), 0) || 29;
      tlLoad(true, '集结远征队', `正在对全塔 ${totalLevels} 关做真实检测，网络项需要十几秒`);
      preview = await api('/api/tower/preview');
      tlLoad(false);
      const chain = preview.floors || [];
      aaSpineInit(preview);
      if (chain.length) aaSetHero(chain[0].start);
      if (!T.autoSkip) setAutoStage('推演完成 · 勇者出发');
      await sleep(420);

      for (const f of chain) {
        if (T.autoSkip) break;
        await aaIntroduceFloor(f);
        if (T.autoSkip) break;
        aaSpineMark(f.id, 'active');
        let handled = 0;
        let killed = 0;
        const total = f.count || (f.levels || []).length;
        for (const ev of f.events || []) {
          if (T.autoSkip) break;
          if (ev.type === 'fight') {
            const res = await aaFight(ev, f);
            if (res === 'done' || res === 'blocked') {
              handled += 1;
              if (res === 'done') killed += 1;
              aaProgress(handled, total);
              aaSpineTick(f.id, killed, total);
            }
          } else if (ev.type === 'camp') {
            await aaCamp(ev, f);
          } else if (ev.type === 'gear') {
            await aaGear(ev, f);
          } else if (ev.type === 'boss') {
            await aaBoss(ev, f);
          } else if (ev.type === 'boss_seal') {
            await aaBossSeal(ev, f);
          }
        }
        if (T.autoSkip) break;
        if (f.cleared) {
          aaSpineMark(f.id, 'ok');
          aaLog(`第 ${f.no} 层 · ${f.name} 通关，阶梯亮起。`, 'gold');
          setAutoStage(`第 ${f.no} 层清空 · 阶梯开启`);
        } else {
          aaSpineMark(f.id, 'fail');
          aaLog(`第 ${f.no} 层 · ${f.name} 还有 ${(f.failed || []).length} 项没过，先记下，继续上一层。`, 'bad');
          setAutoStage(`第 ${f.no} 层结束 · 继续挑战`);
        }
        await sleep(520);
      }

      if (!T.autoSkip) {
        if (preview.final) {
          await aaFinal(preview.final);
          const finOk = !!(preview.final && preview.final.killed);
          aaSpineTick('final', finOk ? 1 : 0, 1);
          aaSpineMark('final', finOk ? 'ok' : 'fail');
        } else if (preview.finalSeal) {
          await aaFinalSeal(preview.finalSeal);
          aaSpineMark('final', 'fail');
        }
      }
    } catch (e) {
      toast(e.message || '自动闯关失败');
    } finally {
      skipped = T.autoSkip;
      T.autoRunning = false;
      T.auto = false;
      T.autoSkip = false;
      T.autoNewGear = null;
      T.busy = false;
      T.walking = false;
      tlLoad(false);
      document.body.classList.remove('auto-running');
      $('#auto-arena').hidden = true;
      $('#aa-intro').hidden = true;
      $('#aa-barrier').hidden = true;
      $('#aa-stamp').hidden = true;
      $('#aa-drop').hidden = true;
      $('#auto-skip').disabled = false;
      $('#auto-skip').textContent = '跳过演出';
      render();
      if (preview) {
        await finishTour(preview, skipped);
      } else {
        document.body.classList.remove('battling');
      }
    }
    return { ok: !!preview };
  }

  $('#auto-skip').addEventListener('click', () => {
    if (!T.autoRunning || T.autoSkip) return;
    T.autoSkip = true;
    setAutoStage('正在跳过演出…');
    const btn = $('#auto-skip');
    btn.disabled = true;
    btn.textContent = '跳过中…';
    $('#aa-intro').hidden = true;
    $('#aa-barrier').hidden = true;
    $('#aa-stamp').hidden = true;
    $('#aa-drop').hidden = true;
  });

  /* ---------------------------------------------------------- 通关 */

  /* 登临塔顶的庆祝过场。只在真实通关时自动播放一次，支持随时跳过。
     所有延迟音符、键盘监听与焦点都在退出时统一清理。 */
  let finisherPlayed = false;
  const FINISHER_MS = 10600;

  function splitFinaleLine() {
    const el = $('#fn-l4');
    if (!el || el.dataset.split === '1') return;
    const text = el.textContent;
    el.textContent = '';
    [...text].forEach((ch, i) => {
      const span = document.createElement('span');
      span.textContent = ch;
      span.style.setProperty('--n', String(i));
      el.appendChild(span);
    });
    el.dataset.split = '1';
  }

  function playFinisher() {
    return new Promise((resolve) => {
      const box = $('#finisher');
      const motion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)');
      if (!box || (motion && motion.matches) || finisherPlayed) { resolve(false); return; }
      finisherPlayed = true;
      splitFinaleLine();
      const previousFocus = document.activeElement;
      const skip = $('#fn-skip');
      const timers = [];
      let done = false;
      const later = (fn, ms) => timers.push(setTimeout(() => { if (!done) fn(); }, ms));
      const finish = () => {
        if (done) return;
        done = true;
        timers.forEach(clearTimeout);
        document.removeEventListener('keydown', onKey, true);
        if (motion && motion.removeEventListener) motion.removeEventListener('change', onMotion);
        skip.onclick = null;
        box.onclick = null;
        box.classList.remove('run');
        box.classList.add('out');
        setTimeout(() => {
          box.hidden = true;
          box.setAttribute('aria-hidden', 'true');
          box.classList.remove('out');
          if (previousFocus && previousFocus.isConnected && previousFocus.focus) previousFocus.focus({ preventScroll: true });
          resolve(true);
        }, 300);
      };
      const onMotion = (e) => { if (e.matches) finish(); };
      const onKey = (e) => {
        if (['Escape', ' ', 'Enter', 'Tab'].includes(e.key)) {
          e.preventDefault();
          e.stopImmediatePropagation();
          if (e.key === 'Tab') skip.focus({ preventScroll: true });
          else finish();
        }
      };
      box.hidden = false;
      box.setAttribute('aria-hidden', 'false');
      void box.offsetWidth;
      box.classList.add('run');
      busyOff();
      document.addEventListener('keydown', onKey, true);
      if (motion && motion.addEventListener) motion.addEventListener('change', onMotion);
      skip.onclick = (e) => { e.stopPropagation(); finish(); };
      box.onclick = (e) => { if (e.target === box) finish(); };
      skip.focus({ preventScroll: true });

      // 柔和的五声音阶，与亮灯和祝词同步；跳过后不遗留延迟音符。
      beep(130.81, .8, 'triangle', .018, 196);
      [261.63, 329.63, 392, 523.25].forEach((f, i) => later(() => beep(f, .22, 'triangle', .025), 800 + i * 300));
      [523.25, 659.25, 783.99, 1046.5].forEach((f, i) => later(() => beep(f, .38, 'triangle', .026), 4400 + i * 180));
      later(finish, FINISHER_MS);
    });
  }

  async function showVictory(d, { animate = false } = {}) {
    const played = animate ? await playFinisher() : false;
    const h = d.hud;
    const sv = d.survival || {};
    $('#victory').hidden = false;
    document.body.classList.add('battling');
    if (!played) sfx.win();

    $('#v-stats').innerHTML = `
      <div><b>${sv.days == null ? '—' : sv.days}</b><span>存活天数</span></div>
      <div><b>${h.hp}</b><span>通关血量</span></div>
      <div><b>Lv.${h.level}</b><span>${esc(h.title)}</span></div>
      <div><b>${fmtDur(d.run.durationSec)}</b><span>通关用时</span></div>`;

    const saved = localStorage.getItem('cc-hero') || '';
    $('#v-name').value = saved;
    if (sv.since) $('#v-since').value = sv.since;
    $('#v-hint').textContent = sv.days == null
      ? '本地没有找到使用痕迹，填一个你记得的日期，存活天数按它计算。'
      : `按${sv.source}推算，你已经在 Claude 里活了 ${sv.days} 天。`;
    $('#v-form').hidden = false;
    $('#v-done').hidden = true;

    $('#v-save').onclick = saveVictory;
    $('#v-skip').onclick = () => { $('#victory').hidden = true; document.body.classList.remove('battling'); };
    $('#v-close').onclick = () => { $('#victory').hidden = true; document.body.classList.remove('battling'); };
    $('#v-board').onclick = () => { $('#victory').hidden = true; document.body.classList.remove('battling'); switchTab('board'); };
  }

  async function saveVictory() {
    const name = $('#v-name').value.trim();
    const since = $('#v-since').value;
    if (!name) { toast('留个名字吧'); return; }
    let days = null;
    if (since) {
      const t = new Date(since + 'T00:00:00').getTime();
      if (!Number.isNaN(t)) days = Math.max(0, Math.floor((Date.now() - t) / 86400000));
    }
    const h = T.data.hud;
    try {
      const res = await api('/api/leaderboard', {
        method: 'POST',
        body: {
          name, days, hp: h.hp, level: h.level, exp: h.exp,
          durationSec: T.data.run.durationSec, title: h.title,
        },
      });
      localStorage.setItem('cc-hero', name);
      renderBoard({ entries: res.entries, stats: res.stats });
      $('#v-form').hidden = true;
      $('#v-done').hidden = false;
      const rank = res.entries.find((e) => Math.abs(e.ts - res.entry.ts) < 0.01);
      $('#v-rank').innerHTML = `
        <div class="vr-no">#${rank ? rank.rank : 1}</div>
        <div class="vr-txt"><b>${esc(name)}</b> 已登上勇士榜<br>
        <span>存活 ${days == null ? '—' : days} 天 · 血量 ${h.hp} · Lv.${h.level} ${esc(h.title)}</span></div>`;
      sfx.levelup();
    } catch (e) {
      toast(e.message);
    }
  }

  /* ---------------------------------------------------------- 勇士榜 */

  function fmtDur(sec) {
    sec = Number(sec || 0);
    if (!sec) return '—';
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    if (m >= 60) return `${Math.floor(m / 60)}h${String(m % 60).padStart(2, '0')}m`;
    if (m) return `${m}m${String(s).padStart(2, '0')}s`;
    return `${s}s`;
  }

  function renderBoard(board) {
    if (!board) return;
    const entries = board.entries || [];
    const stats = board.stats || {};
    if (!entries.length) {
      $('#board-list').innerHTML = `<div class="empty"><svg><use href="#i-empty"/></svg>
        <p>还没有勇士登榜</p><span>击倒塔顶的 Claude 之后，你的名字会出现在这里。</span></div>`;
      $('#board-sub').textContent = '通关后登记战绩，看看谁在这座塔里活得最久。';
      return;
    }
    $('#board-sub').textContent = `${stats.count} 位勇士 · 最长存活 ${stats.bestDays} 天 · 最高血量 ${stats.bestHp}`;

    const medal = (n) => (n === 1 ? '🥇' : n === 2 ? '🥈' : n === 3 ? '🥉' : `<span class="bt-n">${n}</span>`);
    const rows = entries.map((e) => `
      <tr class="${e.rank <= 3 ? 'top' : ''}${e.author ? ' author' : ''}"${e.author && e.note ? ` title="${esc(e.note)}"` : ''}>
        <td class="bt-rank">${medal(e.rank)}</td>
        <td class="bt-name">${esc(e.name)}${e.author ? '<span class="bt-author">作者</span>' : ''}</td>
        <td class="bt-days"><b>${e.days == null ? '—' : e.days}</b> 天</td>
        <td>${e.hp}</td>
        <td>Lv.${e.level}<span class="bt-title">${esc(e.title || '')}</span></td>
        <td>${fmtDur(e.durationSec)}</td>
        <td class="bt-date">${esc(e.clearedAt || '—')}</td>
        <td class="bt-del">${e.author ? '' : `<button data-del-entry="${e.ts}" title="移除">×</button>`}</td>
      </tr>`).join('');

    $('#board-list').innerHTML = `
      <div class="board-table">
        <table>
          <thead><tr>
            <th>#</th><th>勇士</th><th>存活</th><th>血量</th><th>等级</th><th>用时</th><th>通关时间</th><th></th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <p class="board-note">榜单只存在本机 <code>~/.ccclean/leaderboard.json</code>，不上传任何数据。存活天数按本地最早痕迹推算。</p>`;

    $$('#board-list [data-del-entry]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        if (!confirm('从榜单移除这条记录？')) return;
        try {
          const res = await api('/api/leaderboard/delete', { method: 'POST', body: { ts: Number(btn.dataset.delEntry) } });
          renderBoard({ entries: res.entries, stats: res.stats });
        } catch (e) { toast(e.message); }
      });
    });
  }

  async function loadBoard() {
    try {
      const d = await api('/api/leaderboard');
      renderBoard(d);
    } catch (_) {}
  }

  /* ---------------------------------------------------------- 事件 */

  document.addEventListener('click', (e) => {
    const f = e.target.closest('[data-floor]');
    if (f) {
      if (T.autoRunning) return;
      T.floor = f.dataset.floor;
      render();
      return;
    }
    const lv = e.target.closest('[data-fight]');
    if (lv) {
      fight(lv.dataset.fight);
      return;
    }
    const boss = e.target.closest('[data-boss]');
    if (boss && !boss.disabled) {
      fightBoss(boss.dataset.boss);
      return;
    }
    const fin = e.target.closest('[data-final]');
    if (fin && !fin.disabled) {
      fightFinal();
      return;
    }
    const rt = e.target.closest('[data-retry]');
    if (rt) {
      retryFloor(rt.dataset.retry);
      return;
    }
  });

  $('#b-close').addEventListener('click', closeBattle);

  // 地图点击寻路：点地板走过去，点怪物走到它面前撞上去
  $('#floor-body').addEventListener('click', (e) => {
    const fm = e.target.closest('#fmap');
    if (!fm || !T.cells) return;
    const r = fm.getBoundingClientRect();
    const t = r.width / T.cells.w;
    const tx = Math.floor((e.clientX - r.left) / t);
    const ty = Math.floor((e.clientY - r.top) / t);
    if (tx < 0 || ty < 0 || tx >= T.cells.w || ty >= T.cells.h) return;
    walkTo(tx, ty);
  });

  const DIRKEY = {
    arrowup: [0, -1], w: [0, -1],
    arrowdown: [0, 1], s: [0, 1],
    arrowleft: [-1, 0], a: [-1, 0],
    arrowright: [1, 0], d: [1, 0],
  };

  function mapKeysReady(e) {
    if (!T.data || battleOpen || T.walking || T.busy || T.autoRunning) return false;
    if (downed()) return false;
    if (!$('#panel-tower').classList.contains('active')) return false;
    if (!$('#title').hidden || !$('#victory').hidden) return false;
    if (!$('#finisher').hidden) return false;
    if ($('#modal').classList.contains('show')) return false;
    if (/INPUT|TEXTAREA|SELECT/.test(e.target.tagName)) return false;
    return !!T.pos[T.floor];
  }

  document.addEventListener('keydown', (e) => {
    // 免责声明在最上层：按键只用于滚动，未读完不能穿透到标题菜单
    if (noticeVisible()) {
      const b = $('#nt-body');
      const go = $('#nt-go');
      if (e.key === 'Enter') {
        if (go && !go.disabled) { sfx.confirm(); closeNotice(); }
        e.preventDefault(); return;
      }
      if (e.key === 'Escape') {
        if (go && !go.disabled) closeNotice();
        e.preventDefault(); return;
      }
      if (e.key === ' ' && go && !go.disabled) {
        sfx.confirm(); closeNotice(); e.preventDefault(); return;
      }
      if (e.key === 'ArrowDown' || e.key === 'PageDown' || e.key === ' ') {
        if (b) b.scrollTop += (e.key === 'PageDown' ? b.clientHeight * 0.85 : 64);
        e.preventDefault(); return;
      }
      if (e.key === 'ArrowUp' || e.key === 'PageUp') {
        if (b) b.scrollTop -= (e.key === 'PageUp' ? b.clientHeight * 0.85 : 64);
        e.preventDefault(); return;
      }
      return;
    }
    // 营地弹层：Esc / Enter 返回，别让按键穿透到标题菜单
    if (!$('#camp').hidden) {
      if (e.key === 'Escape' || e.key === 'Enter' || e.key === ' ') {
        closeCamp(); e.preventDefault();
      }
      return;
    }
    // 标题画面：↑↓ 选菜单，Enter 确认
    if (titleVisible()) {
      // 焦点在「免责声明」链接上时，交给按钮自己处理 Enter / 空格
      if (e.target && e.target.id === 't-legal') return;
      if (e.key === 'ArrowUp' || e.key === 'w' || e.key === 'W') {
        tSel = (tSel + menuItems().length - 1) % menuItems().length;
        sfx.menu(); renderMenu(); e.preventDefault();
      } else if (e.key === 'ArrowDown' || e.key === 's' || e.key === 'S') {
        tSel = (tSel + 1) % menuItems().length;
        sfx.menu(); renderMenu(); e.preventDefault();
      } else if (e.key === 'Enter' || e.key === ' ') {
        runMenu(menuItems()[tSel].act); e.preventDefault();
      }
      return;
    }
    if (e.key === 'Escape' && battleOpen) { closeBattle(); return; }

    const k = (e.key || '').toLowerCase();
    const dir = DIRKEY[k];
    if (!dir || !mapKeysReady(e)) return;
    e.preventDefault();
    const now = performance.now();
    if (now - T.lastStep < 150) return;   // 按住连走也限速
    T.lastStep = now;
    const p = T.pos[T.floor];
    tryStep(p.x + dir[0], p.y + dir[1]);
  });

  const exp = $('#board-export');
  if (exp) exp.addEventListener('click', async () => {
    try {
      const res = await api('/api/leaderboard/export', { method: 'POST', body: {} });
      toast('已保存到 ' + res.path, 4200);
    } catch (e) { toast(e.message); }
  });

  /* ---------------------------------------------------------- 标题画面 */

  const TOWER_ART = [
    '..........^..........',
    '.........^^^.........',
    '..........l..........',
    '......#.#.#.#.#......',
    '......l#######s......',
    '......l#######s......',
    '......l#######s......',
    '......l#w###w#s......',
    '.#.#..l##w###ws.#.#..',
    '.l##s.l#######s.l##s.',
    '.l##s.l#######s.l##s.',
    '.l##s.l#######s.l##s.',
    '.lw#s.l#w###w#s.lw#s.',
    '.l##s.l#######s.l##s.',
    '.l##s.l#######s.l##s.',
    '.l##s.l#######s.l##s.',
    '.l#ws.l#######s.l#ws.',
    '.l##s.l###w###s.l##s.',
    '.l##s.l#######s.l##s.',
    '.l##s.l#######s.l##s.',
    '.l##s.l###d###s.l##s.',
    '.lw#s.l##sds##s.lw#s.',
    '.l##s#l##sds##s#l##s.',
    '.l##s#l##sds##s#l##s.',
    '.l##s#l##sds##s#l##s.',
    '#####################',
    'sssssssssssssssssssss',
  ];
  const ART_PAL = { '#': '#3d4a80', 'l': '#586aa6', 's': '#2a345e', 'w': '#ffd66b', 'd': '#0a0c12', '^': '#f0c96a' };

  const PIXEL_FONT = {
    C: ['.####', '#....', '#....', '#....', '#....', '#....', '.####'],
    L: ['#....', '#....', '#....', '#....', '#....', '#....', '#####'],
    A: ['.###.', '#...#', '#...#', '#####', '#...#', '#...#', '#...#'],
    U: ['#...#', '#...#', '#...#', '#...#', '#...#', '#...#', '.###.'],
    D: ['####.', '#...#', '#...#', '#...#', '#...#', '#...#', '####.'],
    E: ['#####', '#....', '#....', '####.', '#....', '#....', '#####'],
    T: ['#####', '..#..', '..#..', '..#..', '..#..', '..#..', '..#..'],
    O: ['.###.', '#...#', '#...#', '#...#', '#...#', '#...#', '.###.'],
    W: ['#...#', '#...#', '#...#', '#...#', '#...#', '##.##', '#.#.#'],
    R: ['####.', '#...#', '#...#', '####.', '#.#..', '#..#.', '#...#'],
  };

  function pixelWord(text) {
    const glyphs = [...text].map((ch) => PIXEL_FONT[ch]).filter(Boolean);
    if (!glyphs.length) return '';
    const gap = 1;
    const cols = glyphs.reduce((n, g) => n + g[0].length, 0) + (glyphs.length - 1) * gap;
    let cells = '';
    let offset = 0;
    glyphs.forEach((g) => {
      g.forEach((row, y) => {
        [...row].forEach((ch, x) => {
          if (ch === '#') cells += `<rect x="${offset + x}" y="${y}" width="1" height="1"/>`;
        });
      });
      offset += g[0].length + gap;
    });
    return `<svg class="t-word" viewBox="0 0 ${cols} 7" shape-rendering="crispEdges" aria-hidden="true">
      <g class="word-shadow" transform="translate(.7 .7)">${cells}</g>
      <g class="word-face">${cells}</g>
    </svg>`;
  }

  function pixelArt(rows) {
    let out = '';
    rows.forEach((row, y) => {
      [...row].forEach((ch, x) => {
        const c = ART_PAL[ch];
        if (c) out += `<rect x="${x * 10}" y="${y * 10}" width="10.6" height="10.6" fill="${c}"${ch === 'w' ? ' class="win"' : ''}/>`;
      });
    });
    return `<svg viewBox="0 0 ${rows[0].length * 10} ${rows.length * 10}" class="t-px">${out}</svg>`;
  }

  let tSel = 0;
  let tBusy = false;

  function menuItems() {
    return [
      { act: 'start', label: (T.data && T.data.unlocked) ? '继续游戏' : '开始游戏' },
      { act: 'cruise', label: '挑战历史' },
      { act: 'board', label: '勇士榜' },
      { act: 'privacy', label: '遥测隐私设置' },
      { act: 'camp', label: '勇士营地' },
      { act: 'quit', label: '退出游戏' },
    ];
  }

  function titleVisible() {
    const t = $('#title');
    return t && !t.hidden;
  }

  function renderMenu() {
    const items = menuItems();
    if (tSel >= items.length) tSel = 0;
    $('#t-menu').innerHTML = items.map((m, i) =>
      `<li data-act="${m.act}" tabindex="-1" class="${i === tSel ? 'sel' : ''}"><i>▶</i><span>${esc(m.label)}</span></li>`).join('');
    $$('#t-menu li').forEach((li, i) => {
      li.addEventListener('mouseenter', () => {
        if (tSel !== i) { tSel = i; sfx.menu(); renderMenu(); }
      });
      li.addEventListener('click', () => { tSel = i; runMenu(li.dataset.act); });
    });
  }

  function showTitle() {
    if (T.autoRunning) return;
    const t = $('#title');
    t.hidden = false;
    $('#t-bye').hidden = true;
    $('#t-panel').hidden = false;
    $('#camp').hidden = true;
    document.body.classList.remove('camp-on');
    document.body.classList.add('title-on');
    if (!$('#t-tower').innerHTML) $('#t-tower').innerHTML = pixelArt(TOWER_ART);
    if (!$('#t-logo-art').innerHTML) $('#t-logo-art').innerHTML = pixelWord('CLAUDE') + pixelWord('TOWER');
    makeStars();
    makeEmbers();
    tSel = 0;
    renderMenu();
  }

  function hideTitle() {
    $('#title').hidden = true;
    $('#camp').hidden = true;
    document.body.classList.remove('title-on', 'camp-on');
  }

  function openCamp() {
    $('#camp').hidden = false;
    document.body.classList.add('camp-on');
    setTimeout(() => { const b = $('#camp-back'); if (b) b.focus(); }, 60);
  }

  function closeCamp() {
    $('#camp').hidden = true;
    document.body.classList.remove('camp-on');
    const li = $('#t-menu li[data-act="camp"]');
    if (li) li.focus();
  }

  $('#camp-close').addEventListener('click', closeCamp);
  $('#camp-back').addEventListener('click', closeCamp);
  $('#camp').addEventListener('click', (e) => { if (e.target.id === 'camp') closeCamp(); });

  function makeStars() {
    const box = $('#t-stars');
    if (!box || box.childElementCount) return;
    let h = '';
    for (let i = 0; i < 72; i++) {
      const s = Math.random() < 0.12 ? 3 : Math.random() < 0.48 ? 2 : 1;
      h += `<i style="--sx:${(Math.random() * 100).toFixed(1)}%;--sy:${(Math.random() * 66).toFixed(1)}%;--sd:${(Math.random() * 3.4).toFixed(2)}s;--ss:${s}px"></i>`;
    }
    box.innerHTML = h;
  }

  function makeEmbers() {
    const box = $('#t-embers');
    if (!box || box.childElementCount) return;
    let h = '';
    for (let i = 0; i < 16; i++) {
      h += `<i style="--ex:${(8 + Math.random() * 84).toFixed(1)}%;--ed:${(5 + Math.random() * 5).toFixed(2)}s;--edelay:${(-Math.random() * 9).toFixed(2)}s;--es:${1 + Math.round(Math.random() * 2)}px;--dx:${Math.round(Math.random() * 60 - 30)}px"></i>`;
    }
    box.innerHTML = h;
  }

  async function runMenu(act) {
    if (tBusy) return;
    sfx.confirm();
    if (act === 'start') {
      hideTitle();
      switchTab('tower');
      if (!T.data) await load(false);
      if (T.data) render();
      if (T.data && T.data.tour && T.data.tour.firstRun) {
        await autoRun();
      }
      return;
    }
    if (act === 'cruise') {
      hideTitle();
      switchTab('cruise');
      return;
    }    if (act === 'board') {
      hideTitle();
      switchTab('board');
      return;
    }
    if (act === 'privacy') {
      hideTitle();
      switchTab('privacy');
      return;
    }
    if (act === 'camp') {
      openCamp();
      return;
    }
    if (act === 'quit') {
      try { await api('/api/quit', { method: 'POST', body: {} }); } catch (_) {}
      $('#t-panel').hidden = true;
      $('#t-bye').hidden = false;
    }
  }

  /* ---------------------------------------------------------- 免责声明 */

  const NOTICE_KEY = 'cc.notice.v1';
  // 版本号由服务端注入页面。免责声明改过内容就换版本号，老用户会重读一次——
  // 否则新增的条款（比如「钥匙串条目删了回不来」）永远到不了已经点过同意的人眼前。
  const CC_VERSION = (document.querySelector('meta[name="cc-version"]') || {}).content || '';

  function noticeVisible() {
    const n = $('#notice');
    return !!n && !n.hidden;
  }

  function noticeAcked() {
    if (!CC_VERSION) return false;
    try { return localStorage.getItem(NOTICE_KEY) === CC_VERSION; } catch (_) { return false; }
  }

  function ackNotice() {
    try { localStorage.setItem(NOTICE_KEY, CC_VERSION); } catch (_) {}
  }

  function noticeReadToEnd() {
    const b = $('#nt-body');
    if (!b) return true;
    // 内容没有溢出（窗口很高 / 字号很小）时直接放行，不能把人卡死
    if (b.scrollHeight <= b.clientHeight + 4) return true;
    return b.scrollTop + b.clientHeight >= b.scrollHeight - 12;
  }

  function syncNoticeGate() {
    const go = $('#nt-go');
    const hint = $('#nt-hint');
    if (!go || !hint) return;
    const ok = noticeReadToEnd();
    if (go.disabled === ok) go.disabled = !ok;
    hint.classList.toggle('ok', ok);
    hint.textContent = ok ? '已读完 · 可以进入' : '请向下滚动读完全文';
    const card = go.closest('.nt-card');
    if (card) card.classList.toggle('at-end', ok);
  }

  function showNotice() {
    const n = $('#notice');
    if (!n) return;
    n.hidden = false;
    document.body.classList.add('notice-on');
    const b = $('#nt-body');
    if (b) b.scrollTop = 0;
    syncNoticeGate();
  }

  function closeNotice() {
    const n = $('#notice');
    if (!n) return;
    n.hidden = true;
    document.body.classList.remove('notice-on');
    ackNotice();
    // 同时落一份到本机文件：localStorage 按端口隔离，换端口不该再弹一次
    fetch('/api/notice', { method: 'POST', headers: ccHeaders(), body: '{}' }).catch(() => {});
    if (titleVisible()) {
      const li = $('#t-menu li.sel');
      if (li) li.focus();
    }
  }

  (function bindNotice() {
    const go = $('#nt-go');
    const body = $('#nt-body');
    if (!go || !body) return;
    go.addEventListener('click', () => {
      if (go.disabled) return;
      sfx.confirm();
      closeNotice();
    });
    body.addEventListener('scroll', syncNoticeGate, { passive: true });
    window.addEventListener('resize', syncNoticeGate);
    const link = $('#t-legal');
    if (link) {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        sfx.menu();
        showNotice();
      });
    }
  })();

  /* ---------------------------------------------------------- 启动 */

  window.Tower = {
    reload: (rescan) => load(rescan),
    refresh: () => { if (!T.data) load(false); else render(); },
    refreshBoard: loadBoard,
    refreshSettle,
    refreshCruise,
    showTitle,
    autoRun,
  };

  // #tower:<id> 深链直达关卡（验收用），其余情况都停在标题画面
  if (!/^#tower:.+/.test(BOOT_HASH)) showTitle();

  // 版本号以后端为准，避免 HTML / app.py / Info.plist 三处手改后对不上
  fetch('/api/meta', { headers: ccHeaders() }).then((r) => r.json()).then((d) => {
    if (d && d.version) {
      const el = $('#t-ver');
      if (el) el.textContent = 'v' + d.version;
    }
  }).catch(() => {});

  // 首次启动先读免责声明；之后可在标题画面右下角重新打开。
  // localStorage 命中就直接跳过，没命中再问一次后端——端口变了也不会重弹。
  if (!noticeAcked()) {
    fetch('/api/notice', { headers: ccHeaders() })
      .then((r) => r.json())
      .then((d) => {
        if (d && d.acked) { ackNotice(); return; }
        showNotice();
      })
      .catch(() => showNotice());
  }

  if (new URLSearchParams(location.search).get('demo') === 'finisher') {
    window.Tower.previewFinisher = async () => {
      finisherPlayed = false;
      hideTitle();
      $('#notice').hidden = true;
      document.body.classList.remove('notice-on');
      await showVictory({ hud: { hp: 160, level: 12, title: '登顶勇士' },
        survival: { days: 35, source: '演示数据' }, run: { durationSec: 252 } }, { animate: true });
      $('#v-form').hidden = true;
      $('#v-done').hidden = false;
      $('#v-rank').innerHTML = '<div class="vr-txt">演示战绩 · 不写入本机勇士榜</div>';
    };
  } else {
    load(false);
  }
})();
