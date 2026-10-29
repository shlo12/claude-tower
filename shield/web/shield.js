/* Claude Shield · 哨兵 —— 面板渲染
   全部状态由 Swift 侧推送，页面自己不读系统、不轮询。
   页面只做两件事：把快照画出来、把点击发回去。 */

(function () {
  'use strict';

  var $ = function (s) { return document.querySelector(s); };
  var post = function (msg) {
    try { window.webkit.messageHandlers.shield.postMessage(msg); } catch (e) { /* 开发态直接用浏览器打开时没有桥 */ }
  };

  var S = { level: 1, enabled: true, paused: false, verdict: 'idle' };
  var pendingLv2 = 0;   // 二次确认的计时器句柄

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function hhmmss(ts) {
    if (!ts) return '--:--';
    var d = new Date(ts * 1000);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function clock(ts) {
    if (!ts) return '';
    var d = new Date(ts * 1000);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function age(ts) {
    if (!ts) return '';
    var s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 90) return '刚刚';
    if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
    if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
    return Math.floor(s / 86400) + ' 天前';
  }

  // 每行左边一个状态标记（CSS 按 data-st 画 ✓ / ! / × / –）。
  // 值本身只在异常时上色：整列都绿会让人看不出哪一项真的需要处理。
  function setFact(el, text, state) {
    var st = state || 'off';
    var li = el.closest ? el.closest('li') : null;
    if (li) li.dataset.st = st;
    el.className = st === 'warn' ? 'warn' : st === 'bad' ? 'bad'
      : st === 'off' ? 'muted' : '';
    el.textContent = text == null ? '' : String(text);
  }

  // 两行标签由 JS 换，原始文案留在 data-* 上：确认态结束后照原样写回，
  // 不用在 JS 里再抄一份中文。
  function segText(b, title, sub) {
    b.querySelector('.lv-title').textContent = title;
    b.querySelector('.lv-sub').textContent = sub;
  }

  function resetSegLabels() {
    Array.prototype.forEach.call(document.querySelectorAll('#seg button'), function (b) {
      segText(b, b.dataset.name, b.dataset.sub);
      b.classList.remove('asking');
    });
  }

  function render(p) {
    S = Object.assign(S, p);

    $('#ver').textContent = 'v' + (p.version || '1.0.0');
    document.body.classList.toggle('paused', !!p.paused);

    // ---- 主状态 ----
    var st = $('#state');
    // 待命不等于中立：能启动就给绿灯，缺塔或被挡住就给黄灯。
    // verdict 仍然是 idle（不参与报警），这里只影响状态卡的颜色。
    var v = p.verdict || 'idle';
    if (!p.paused && v === 'idle' && p.idleState === 'ready') v = 'safe';
    if (!p.paused && v === 'idle' && p.idleState && p.idleState !== 'ready') v = 'warn';
    st.dataset.v = v;
    $('#st-title').textContent = p.paused ? '已暂停' : (p.title || '待命');
    $('#st-note').textContent = p.paused
      ? '哨兵暂时下班，这段时间不做任何检查。'
      : (p.note || '');

    // ---- 缺塔提醒 ----
    // 只装了 Shield 时，指标行看起来一切正常，但时区漂移和 UDP 出口
    // 根本没法比对。这条横幅要一直挂着，直到塔真的写进基线。
    var tw = $('#tower-warn');
    var towerState = p.towerState ||
      ((p.baselineTz || p.egressMask) ? 'ok' : 'missing');
    if (towerState === 'missing') {
      tw.hidden = false;
      $('#tower-note').textContent = '没有塔的基线：时区漂移和 UDP 出口都比对不了。';
    } else if (towerState === 'stale') {
      tw.hidden = false;
      $('#tower-note').textContent = '塔的基线过期了：UDP 出口暂时比对不了，去塔里再扫一次。';
    } else {
      tw.hidden = true;
    }

    // ---- 塔留下的设置漂移 ----
    // IPv6 被系统/别的工具重新打开，或者分流规则被订阅更新冲掉。
    // 两件事的修法都在塔里，所以共用一条横幅、一个「打开塔」。
    var driftNotes = [];
    if (p.ipv6Drift) {
      driftNotes.push('Wi-Fi 的 IPv6 又被打开了');
    }
    if (p.ruleDrift) {
      var missing = p.ruleMissing || [];
      var sample = missing.slice(0, 2).join('、');
      driftNotes.push('分流规则被改过'
        + (sample ? '：' + sample + (missing.length > 2 ? ' 等 ' + missing.length + ' 条' : '')
                  : ''));
    }
    var dw = $('#drift-warn');
    if (driftNotes.length) {
      dw.hidden = false;
      $('#drift-note').textContent = driftNotes.join('；') + '。修好在塔里，哨兵不会自己改系统。';
    } else {
      dw.hidden = true;
    }

    // ---- 开机自启 ----
    // 只在用户确实开过的时候提醒：没点过的人不该看见「失效」。
    var lw = $('#login-warn');
    lw.hidden = !p.loginBroken;
    if (p.loginBroken) {
      $('#login-note').textContent = '开机自启失效了：启动项被移除，或还指着旧位置。';
    }

    // ---- 进程 ----
    // Claude 没在跑不是错误，只是待命：给灰色横杠，不给红叉。
    setFact($('#f-claude'), p.claude ? '运行中' : '未运行', p.claude ? 'ok' : 'off');

    // ---- 出口 ----
    var iface = p.tunIface || '';
    var fr = $('#f-route');
    if (!iface) {
      setFact(fr, '没读到', 'off');
    } else if (p.tun) {
      setFact(fr, iface + ' · 隧道', 'ok');
    } else if (p.sysProxy) {
      // 系统代理不需要路由接管，直连是这种模式的正常样子
      setFact(fr, iface + ' · 直连', 'off');
    } else {
      setFact(fr, iface + ' · 直连', 'bad');
    }
    fr.title = '发往公网的包实际走哪张网卡。TUN 客户端常把 0/0 拆成更细的前缀，' +
      'default 仍留在 Wi-Fi，所以这里按内核的最长前缀匹配来判，不只读 default。';

    var tunState = p.tun ? 'ok' : p.sysProxy ? 'off' : 'bad';
    setFact($('#f-tun'), p.tun ? '已接管' : '未接管', tunState);
    // 系统代理未开启不算错：TUN 在位，或者压根没出口时，由上面几行表态。
    var fc = $('#f-connections');
    setFact(fc, p.connectionsState === 'direct' ? '公网物理路由' : p.connectionsState === 'local' ? '本次为本地代理连接' : '未确认', p.connectionsState === 'direct' ? 'bad' : p.connectionsState === 'local' ? 'ok' : 'warn');
    fc.title = p.connectionsDetail || '无法证明全部连接经过代理';
    if (p.connectionsState === 'local') fc.title += '；尚未确认客户端最终使用代理节点还是 DIRECT';
    $('#connections-note').textContent = fc.title;
    setFact($('#f-proxy'), p.sysProxy ? '已开启' : '未开启', p.sysProxy ? 'ok' : 'off');

    var fe = $('#f-egress');
    if (!p.egressMask) {
      // 没基线不是「不适用」：时区漂移和 UDP 比对都做不了，值得标黄。
      setFact(fe, '塔还没记过', 'warn');
    } else {
      var parts = [];
      if (p.country) parts.push(p.country);
      parts.push(p.egressMask);
      var egressState;
      if (!p.egressAt) {
        parts.push('时间未知');
        egressState = 'warn';
      } else {
        parts.push(age(p.egressAt));
        // 打勾只代表这份基线还新鲜、能拿来比对，不代表出口现在还在。
        egressState = p.maskFresh ? 'ok' : 'warn';
      }
      setFact(fe, parts.join(' · '), egressState);
    }
    fe.title = '塔上次扫描记下的出口，不是当前出口；只存打码地址。超过 24 小时就不拿它判 UDP 泄漏。';

    // ---- 解析 ----
    // 出口不在的时候 DNS 和 STUN 都压根没跑：那时候查一次就等于自己泄漏一次。
    var exitReady = p.tun || p.sysProxy;

    var dns = $('#f-dns');
    if (!exitReady) {
      setFact(dns, '出口不在，没查', 'off');
      dns.title = '只在出口在位时才查：出口不在的时候查 DNS，等于自己制造一次泄漏。';
    } else if (!p.dnsChecked) {
      setFact(dns, '没查成', 'off');
      dns.title = '这次没拿到结果，不降级判定——网络抖一下就报警，人会很快学会无视通知。';
    } else if (p.dnsFake) {
      setFact(dns, '隧道内 · ' + p.dns, 'ok');
      dns.title = 'claude.ai 解析到了假地址（fake-ip），说明 DNS 被客户端接管了。';
    } else if (p.dnsSuspect) {
      setFact(dns, p.dns + '（直连解析）', 'warn');
      dns.title = '解析到了真实地址。TUN 开着却拿不到假地址，说明 DNS 没被接管——' +
        '域名分流规则可能失效。用 redir-host 模式的话这是正常的。';
    } else {
      // 系统代理本来就不接管 DNS，这里只是「不适用」，不是「通过」
      setFact(dns, p.dns + '（直连解析）', 'off');
      dns.title = '系统代理本来就不接管 DNS，拿到真实地址是正常的——不参与判定。';
    }

    var udp = $('#f-udp');
    var ips = p.stun || [];
    if (!exitReady) {
      setFact(udp, '出口不在，没查', 'off');
      udp.title = '只在出口在位时才打 STUN：出口不在的时候发 UDP，等于自己把真实地址送出去。';
    } else if (!p.stunChecked) {
      setFact(udp, '没探到', 'off');
      udp.title = '四个 STUN 节点都没回。一次超时不作结论，也不报警。';
    } else if (p.stunLeak) {
      setFact(udp, '分裂 · ' + ips.join(' / '), 'warn');
      udp.title = '境外节点给出了两个不同的出口地址，说明一部分 UDP 走了直连。';
    } else if (!p.towerData || !p.maskFresh || !p.egressMask) {
      // 没有基线时只能证明「STUN 有回包」，证明不了它和 HTTP 出口是同一条。
      // 给绿灯等于替一个没做的比对下结论。
      setFact(udp, ips.join(' / ') + ' · 无基线', 'off');
      udp.title = '没有可用的塔基线，只能确认 STUN 有回包，判断不了它是不是同一个出口。';
    } else {
      setFact(udp, ips.join(' / '), 'ok');
      udp.title = 'STUN 打回来的地址（含国内节点）。国内节点回真实地址是分流规则的正确结果，不参与判定。';
    }

    // ---- 传输 ----
    // 走到 Anthropic 的 HTTPS 有没有真的通。它不进主判定：一次握手成功
    // 只说明那一刻这条路能走，说明不了之后每个包都安全。
    var ft = $('#f-transport');
    var bt = $('#btn-transport');
    bt.textContent = '诊断传输';
    bt.title = '用当前系统路径向 api.anthropic.com 和 claude.ai 各发一个 HEAD：'
      + '不下载正文、不带 Cookie、不带账号。';
    if (!exitReady) {
      setFact(ft, '出口不在，没测', 'off');
      ft.title = '只在出口在位时测。出口不在的时候连 Anthropic，测的是这条路本身走不通，'
        + '不能拿来判断代理。';
      bt.disabled = true;
    } else if (!p.transportChecked) {
      setFact(ft, '还没测', 'off');
      ft.title = '哨兵会按周期重测；也可以点「诊断传输」立刻跑一次。';
      bt.disabled = false;
    } else {
      var tst = p.transportState === 'ok' ? 'ok'
        : p.transportState === 'bad' ? 'bad'
        : p.transportState === 'warn' ? 'warn' : 'off';
      setFact(ft, p.transportLabel || '—', tst);
      ft.title = (p.transportDetail || '')
        + (p.transportAt ? '（' + age(p.transportAt) + '测的）' : '');
      bt.disabled = false;
    }

    // ---- 时间 ----
    // 没有基线时「当前时区」无从比对，给横杠而不是勾
    setFact($('#f-tz'), p.tz || '未知',
            p.tz && p.baselineTz ? (p.tzDrift ? 'warn' : 'ok') : 'off');

    var fb = $('#f-btz');
    setFact(fb, p.baselineTz || '塔还没记过', p.baselineTz ? 'ok' : 'warn');
    fb.title = '塔扫描时记下的时区。哨兵不会自动改；要改只能点下面的按钮、过一次系统授权。';

    var fa = $('#f-at');
    if (p.lastAt) {
      setFact(fa, clock(p.lastAt) + ' · 每 ' + (p.interval || 30) + ' 秒', 'ok');
    } else {
      setFact(fa, '还没跑过', 'off');
    }
    fa.title = '上一次巡检的时刻和当前周期。周期下限 5 秒，免得 ps/netstat 变成常驻负载。';

    // ---- 自动更新 ----
    // 哨兵只负责发现版本。下载、校验、换应用都在塔里做，
    // 所以这里最多给一个「去塔里更新」，不在菜单栏里动手。
    var fu = $('#f-update');
    var up = p.update || {};
    var bu = $('#btn-update');
    if (!up.configured) {
      setFact(fu, '未配置', 'off');
      fu.title = '塔里还没有填更新源。打开塔 → 隐私设置 → 自动更新。';
      bu.hidden = true;
    } else if (up.newer) {
      setFact(fu, up.version ? up.version + ' 可用' : '有新版本', 'warn');
      fu.title = '新版由塔下载并校验，安装要你在塔里点确认。'
        + (up.error ? '（上次检查出错：' + up.error + '）' : '');
      bu.hidden = false;
      $('#update-ver').textContent = up.version || up.shieldVersion || '';
    } else if (up.error) {
      setFact(fu, '检查失败', 'warn');
      fu.title = up.error + (up.checkedAt ? '（' + age(up.checkedAt) + '）' : '');
      bu.hidden = true;
    } else if (!up.autoCheck) {
      setFact(fu, '自动检查已关', 'off');
      fu.title = '塔里的自动检查关了，仍可在塔里手动检查。';
      bu.hidden = true;
    } else if (up.checkedAt) {
      setFact(fu, '已是最新 · ' + age(up.checkedAt), 'ok');
      fu.title = '哨兵按塔里设的间隔查 GitHub Releases，只读版本，不下载。';
      bu.hidden = true;
    } else {
      setFact(fu, '还没查过', 'off');
      bu.hidden = true;
    }

    // 时区漂移时给一个能按的按钮。写系统设置要管理员密码，
    // 所以只在真的漂了的时候出现，且按钮上写明要密码。
    var fix = $('#btn-fixtz');
    if (p.tzDrift && p.baselineTz) {
      fix.hidden = false;
      $('#fix-tz').textContent = p.baselineTz;
    } else {
      fix.hidden = true;
    }

    // ---- 模式 ----
    Array.prototype.forEach.call(document.querySelectorAll('#seg button'), function (b) {
      var on = Number(b.dataset.lv) === Number(p.level);
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      b.disabled = !p.enabled;
    });
    // 4 秒确认窗口里重绘，不能把「确认开启」擦回默认文案：
    // 用户点第二下时看到的是正常按钮，会以为第一下没生效。
    if (!pendingLv2) resetSegLabels();

    var hint = $('#lv-hint');
    if (!p.enabled) {
      hint.innerHTML = '已停用。勾选下方「继续值守」才会重新巡检。';
    } else if (Number(p.level) >= 2) {
      hint.innerHTML = '戒严：启动后检查，出口、DNS、UDP 或时区不达标会请求退出 Claude；运行中出口中断也会终止。<b>不保证检查前没有联网</b>，未保存工作可能丢失。';
    } else {
      hint.innerHTML = '瞭望：持续检测并提醒，不会终止 Claude。需要自动拦截时可切换「戒严」。';
    }

    // ---- 操作按钮 ----
    var login = $('#btn-login');
    login.classList.toggle('on', !!p.loginItem && !p.loginBroken);
    login.textContent = p.loginItem
      ? (p.loginBroken ? '自启待修' : '已开机自启')
      : '开机自启';

    var pause = $('#btn-pause');
    pause.textContent = p.paused ? '继续值守' : '暂停 30 分钟';

    // ---- 命中记录 ----
    var list = $('#hits');
    var hits = (p.hits || []).slice().reverse();
    if (!hits.length) {
      list.innerHTML = '<li class="empty">还没有记录。哨兵一切正常。</li>';
    } else {
      list.innerHTML = hits.map(function (h) {
        var label = h.kind === 'connection' ? '连接路由异常' : h.kind === 'danger' ? '出口已断'
          : h.kind === 'warn' ? '出口存疑'
          : h.kind === 'takeover' ? '代理未接管'
          : h.kind === 'dns' ? 'DNS 未接管'
          : h.kind === 'stun' ? 'UDP 出口分裂'
          : h.kind === 'notower' ? '缺塔基线'
          : h.kind === 'kill' ? '终止 Claude'
          : h.kind === 'gate' ? '拦下启动'
          : h.kind === 'fixtz' ? '改时区'
          : h.kind;
        // kill 也用红色：它和 danger 是同一件事的两步，分成两种颜色反而看不懂。
        // takeover 同样归红：客户端在跑却没接管，流量这会儿是直连的。
        // gate 是最重的一步——连启动都不让，和 kill 同一个色。
        // dns / stun / notower 归到 gold：它们不是「断了」，是「规则没做全」。
        var cls = h.kind === 'kill' || h.kind === 'takeover' || h.kind === 'gate' ? 'danger'
          : h.kind === 'dns' || h.kind === 'stun' || h.kind === 'notower' ? 'warn'
          : h.kind === 'fixtz' ? 'safe'
          : h.kind;
        return '<li title="' + esc(h.note) + '">' +
          '<i class="k ' + esc(cls) + '"></i>' +
          '<time>' + hhmmss(h.ts) + '</time>' +
          '<span>' + esc(label) + '</span>' +
          '</li>';
      }).join('');
    }
  }

  // ---- 事件 ----

  document.querySelectorAll('#seg button').forEach(function (b) {
    b.addEventListener('click', function () {
      var lv = Number(b.dataset.lv);

      // 点观察档就把还没确认的武装撤掉：用户改主意了。
      if (lv === 1 && pendingLv2) {
        clearTimeout(pendingLv2);
        pendingLv2 = 0;
        resetSegLabels();
      }
      if (lv === S.level) return;

      // 戒严会结束进程，必须二次确认。第一次点只把按钮改成「确认开启」，
      // 4 秒内再点一次才真的武装。确认文案要明确会结束 Claude。
      if (lv >= 2) {
        if (pendingLv2) {
          clearTimeout(pendingLv2);
          pendingLv2 = 0;
          resetSegLabels();
          post({ action: 'level', value: lv });
        } else {
          resetSegLabels();
          b.classList.add('asking');
          segText(b, '确认开启',
                  '4 秒内再点一次 · 会结束 Claude');
          pendingLv2 = setTimeout(function () {
            pendingLv2 = 0;
            resetSegLabels();
          }, 4000);
        }
        return;
      }
      post({ action: 'level', value: lv });
    });
  });

  $('#btn-now').addEventListener('click', function () { post({ action: 'now' }); });
  $('#btn-transport').addEventListener('click', function () {
    // 探测结果会随下一帧推送回来，render() 负责把按钮文字改回去。
    var b = $('#btn-transport');
    if (b.disabled) return;
    b.disabled = true;
    b.textContent = '诊断中…';
    post({ action: 'transport' });
  });
  $('#btn-open').addEventListener('click', function () { post({ action: 'opentower' }); });
  $('#btn-tower').addEventListener('click', function () { post({ action: 'opentower' }); });
  $('#btn-drift').addEventListener('click', function () { post({ action: 'opentower' }); });
  $('#btn-relogin').addEventListener('click', function () { post({ action: 'login' }); });
  $('#btn-update').addEventListener('click', function () { post({ action: 'update' }); });
  $('#btn-login').addEventListener('click', function () { post({ action: 'login' }); });
  $('#btn-log').addEventListener('click', function () { post({ action: 'log' }); });
  // 改时区会弹系统密码框，那就是确认步骤本身，不再加一次二次点击
  $('#btn-fixtz').addEventListener('click', function () { post({ action: 'fixtz' }); });
  $('#btn-pause').addEventListener('click', function () {
    post(S.paused ? { action: 'resume' } : { action: 'pause', minutes: 30 });
  });
  $('#btn-quit').addEventListener('click', function () { post({ action: 'quit' }); });

  window.SHIELD = { update: render };
})();
