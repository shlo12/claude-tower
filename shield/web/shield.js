/* CC Shield · 哨兵 —— 面板渲染
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
    document.body.classList.toggle('paused', !!p.paused || p.enabled === false);

    var strict = p.enabled && !p.paused && Number(p.level) >= 2;
    document.body.classList.toggle('strict-session', strict);

    // ---- 主状态 ----
    var st = $('#state');
    // 待命不等于中立：能启动就给绿灯，缺塔或被挡住就给黄灯。
    // verdict 仍然是 idle（不参与报警），这里只影响状态卡的颜色。
    var v = p.verdict || 'idle';
    if (strict && !p.sessionActive) v = p.claude ? 'danger' : 'warn';
    if (!p.paused && v === 'idle' && p.idleState === 'ready') v = 'safe';
    if (!p.paused && v === 'idle' && p.idleState && p.idleState !== 'ready') v = 'warn';
    if (p.enabled === false || p.paused) v = 'idle';
    st.dataset.v = v;
    $('#st-title').textContent = p.enabled === false ? '已停用' : p.paused ? '已暂停' : (strict && !p.sessionActive ? '需检查后启动' : (p.title || '待命'));
    $('#st-note').textContent = p.enabled === false ? '哨兵未值守，请点击继续值守后重新检查。' : p.paused
      ? '哨兵暂时下班，这段时间不做任何检查。'
      : (strict && !p.sessionActive ? p.sessionMessage : (p.note || ''));

    // ---- 准入会话 ----
    // 启动按钮挂在状态卡右上角，不放在下面的会话框里：戒严档下这一屏
    // 还有四组指标，唯一的启动入口沉在底部，等于要用户先滚一段才找得到。
    var start = $('#btn-start');
    start.hidden = !strict || !!p.claude || !!p.sessionActive;
    start.disabled = !!p.sessionStarting;
    start.textContent = p.sessionStarting ? '检查中…' : '检查后启动';

    var status = $('#session-status');
    status.textContent = p.sessionMessage || '请先检查并启动';
    status.hidden = status.textContent === $('#st-note').textContent;

    // 会话框只负责「正在使用」这一段：结束按钮，加上准入范围说明。
    var ending = !!p.claude || !!p.sessionActive || !!p.sessionStarting;
    $('#btn-session-end').hidden = !ending;
    $('#btn-session-end').disabled = !ending;

    var session = $('#session-panel');
    session.hidden = !strict;
    session.classList.toggle('bare', !ending && status.hidden);

    // ---- 出口变了 ----
    // 哨兵测到的出口和基线对不上时不直接改基线：跟着新值走，真泄漏
    // 也会被记成正常。这里把两个地址摊开，让用户自己认一次。
    var ew = $('#egress-warn');
    if (p.egressSeen) {
      var baseTxt = [p.country, p.egressMask].filter(Boolean).join(' · ') || '未知';
      var seenTxt = [p.egressSeenCountry, p.egressSeen].filter(Boolean).join(' · ');
      ew.hidden = false;
      $('#egress-note').textContent = '出口和基线对不上：基线 ' + baseTxt
        + '，现在测到 ' + seenTxt
        + (p.egressSeenAt ? '（' + age(p.egressSeenAt) + '起）' : '')
        + '。是你自己换的节点才确认，确认后才会拿新出口比对。';
    } else {
      ew.hidden = true;
    }

    // ---- 缺基线提醒 ----
    // 没有基线时，指标行看起来一切正常，但时区漂移和 UDP 出口
    // 根本没法比对。出口基线哨兵会自己补，时区基线只有塔能建。
    var tw = $('#tower-warn');
    var towerState = p.towerState ||
      ((p.baselineTz || p.egressMask) ? 'ok' : 'missing');
    if (towerState === 'missing') {
      tw.hidden = false;
      $('#tower-note').textContent = '还没有基线：时区要打开主窗口扫一次，出口哨兵会自己测。';
    } else if (towerState === 'stale' && !p.egressSeen) {
      // 出口待确认时上面那条横幅已经说清楚了，这里不再叠一句「过期」。
      tw.hidden = false;
      $('#tower-note').textContent = '出口基线过期了：UDP 出口暂时比对不了，哨兵会自动重测。';
    } else {
      tw.hidden = true;
    }

    // ---- 塔留下的设置漂移 ----
    // IPv6 被系统/别的工具重新打开，或者分流规则被订阅更新冲掉。
    // 两件事的修法都在塔里，所以共用一条横幅、一个「打开主窗口」。
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
      $('#drift-note').textContent = driftNotes.join('；') + '。请在魔塔里预览处理，哨兵不会自己改系统。';
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

    $('#vm-network-row').hidden = !p.vmManaged;
    if (p.vmManaged) {
      setFact($('#f-vm-network'), p.vmProtected ? '固定链路 · 已核验' : '未通过', p.vmProtected ? 'ok' : 'bad');
      $('#f-vm-network').title = p.vmIssue || 'pf 持续限制客机出口；关闭界面不会解除网络保护。';
    }
    // ---- 出口 ----
    var iface = p.tunIface || '';
    var fr = $('#f-route');
    if (p.upstream) {
      setFact(fr, (iface || '本机路由') + ' · 上游路径未确认', 'off');
    } else if (!iface) {
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

    var tunState = p.upstream ? 'off' : p.tun ? 'ok' : p.sysProxy ? 'off' : 'bad';
    setFact($('#f-tun'), p.upstream ? '本机不适用' : p.tun ? '已接管' : '未接管', tunState);
    // 系统代理未开启不算错：TUN 在位，或者压根没出口时，由上面几行表态。
    var fc = $('#f-connections');
    setFact(fc, p.connectionsState === 'direct' ? '公网物理路由' : p.connectionsState === 'local' ? '本次为本地代理连接' : '未确认', p.connectionsState === 'direct' ? 'bad' : p.connectionsState === 'local' ? 'ok' : 'warn');
    fc.title = p.connectionsDetail || '无法证明全部连接经过代理';
    if (p.connectionsState === 'local') fc.title += '；尚未确认客户端最终使用代理节点还是 DIRECT';
    $('#connections-note').textContent = fc.title;
    setFact($('#f-proxy'), p.vmManaged ? 'TUN 接管 · 不要求' : p.sysProxy ? '已开启' : '未开启', p.vmManaged ? 'off' : p.sysProxy ? 'ok' : 'off');

    setFact($('#f-policy'), p.sessionChecked ? (p.sessionMode === 'global' ? '全局' : (p.sessionMode === 'rule' ? '规则' : p.sessionMode || '未知')) : '未确认', p.sessionChecked ? (p.sessionMode === 'global' ? 'ok' : (strict ? 'warn' : 'off')) : 'off');
    if (p.vmManaged) setFact($('#f-policy'), p.vmProtected ? '规则全代理 · 已核验' : '规则未确认', p.vmProtected ? 'ok' : 'warn');
    if (p.upstream) setFact($('#f-policy'), '上游模式 · 本机不适用', 'off');
    $('#f-policy').title = p.upstream ? '上游的运行模式无法通过本机接口确认；准入依赖实测证据。' : p.sessionChecked ? '从正在运行的代理本机接口读取；模式本身不能证明每条连接的路径。' : '无法从本机控制接口确认实际模式；戒严需要这份证据。';

    var fe = $('#f-egress');
    if (!p.egressMask) {
      // 没基线不是「不适用」：UDP 比对做不了，值得标黄。
      setFact(fe, '还没测到', 'warn');
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
    fe.title = '基线出口，不是当前出口；只存打码地址。哨兵每天自己测一次续期，超过 24 小时或出口变了就不拿它判 UDP 泄漏。';

    // ---- 解析 ----
    // 出口不在的时候 DNS 和 STUN 都压根没跑：那时候查一次就等于自己泄漏一次。
    // 上游开关允许发起探测；每项仍按实际返回证据显示。
    var exitReady = p.vmManaged ? p.vmProtected && p.tun : p.upstream || p.tun || p.sysProxy;

    var dns = $('#f-dns');
    if (!exitReady) {
      setFact(dns, '出口不在，没查', 'off');
      dns.title = '只在出口在位时才查：出口不在的时候查 DNS，等于自己制造一次泄漏。';
    } else if (!p.dnsChecked) {
      setFact(dns, '没查成', 'off');
      dns.title = '这次没拿到结果，不降级判定——网络抖一下就报警，人会很快学会无视通知。';
    } else if (p.upstream && !p.dnsFake) {
      setFact(dns, p.dns + '（真实地址）', 'off');
      dns.title = '上游透明代理不要求 fake-ip；查询成功不等于路径已确认，请结合解析出口与其他准入证据。';
    } else if (p.dnsFake) {
      setFact(dns, '隧道内 · ' + p.dns, 'ok');
      dns.title = 'claude.ai 解析到了假地址（fake-ip），说明 DNS 被客户端接管了。' +
        '这只证明查询被截走，证明不了后面由谁解析——看下一行。';
    } else if (p.dnsSuspect) {
      setFact(dns, p.dns + '（直连解析）', 'warn');
      dns.title = '解析到了真实地址。TUN 开着却拿不到假地址，说明 DNS 没被接管——' +
        '域名分流规则可能失效。用 redir-host 模式的话这是正常的。';
    } else {
      // 系统代理本来就不接管 DNS，这里只是「不适用」，不是「通过」
      setFact(dns, p.dns + '（直连解析）', 'off');
      dns.title = '系统代理本来就不接管 DNS，拿到真实地址是正常的——不参与判定。';
    }

    // ---- 解析出口 ----
    // 上一行只说「查询被接管了」。这一行回答「真正解析的是谁」——
    // 第三方泄漏测试量的是这一层，漏了它就会出现「外面查出国内 DNS、我们自己全绿」。
    var dnsEg = $('#f-dns-egress');
    var egOrg = (p.dnsResolverOrg || p.dnsResolverCountry || '');
    if (egOrg.length > 18) egOrg = egOrg.slice(0, 18) + '…';
    if (!exitReady) {
      setFact(dnsEg, '出口不在，没查', 'off');
      dnsEg.title = '只在出口在位时才查：没有出口时查一次，等于自己制造一次泄漏。';
    } else if (!p.dnsResolverChecked) {
      setFact(dnsEg, '没查成', 'off');
      dnsEg.title = '这次没拿到解析器出口，不降级判定——拿不到证据就不下结论。';
    } else if (!p.dnsResolverCountry) {
      setFact(dnsEg, p.dnsResolver + ' · 归属未确认', 'off');
      dnsEg.title = '解析器地址取到了，但归属查询没有响应；不替用户猜国家。';
    } else if (p.dnsEgressSuspect) {
      setFact(dnsEg, (egOrg || '国内解析器') + ' · ' + p.dnsResolver, 'warn');
      dnsEg.title = '真正做递归的是国内解析器。fake-ip 只截住了查询，真实解析仍由它完成——' +
        '你访问的域名它都看得见。把客户端的 nameserver 换成境外 DoH，并让 DNS 查询跟着规则走节点。';
    } else if (p.country && p.dnsResolverCountry && p.dnsResolverCountry !== p.country) {
      setFact(dnsEg, (egOrg || p.dnsResolverCountry) + ' · ' + p.dnsResolver, 'off');
      dnsEg.title = '解析器归属 ' + p.dnsResolverCountry + '，出口在 ' + p.country +
        '：两者不同。递归本身不在国内，但第三方探针会把「DNS 国家」一项标红。' +
        '想让这一项变绿，把 nameserver 换成与出口同区的境外 DoH。';
    } else {
      setFact(dnsEg, (egOrg || p.dnsResolverCountry) + ' · ' + p.dnsResolver, 'ok');
      dnsEg.title = '解析器出口不在国内。这一行和上面「有没有被接管」是两个问题：' +
        '接管看假地址，这一行看真正做递归的那台解析器。';
    }

    var udp = $('#f-udp');
    var ips = p.stun || [];
    if (!exitReady) {
      setFact(udp, '出口不在，没查', 'off');
      udp.title = '只在出口在位时才打 STUN：出口不在的时候发 UDP，等于自己把真实地址送出去。';
    } else if (p.vmManaged && p.vmUDPBlocked && !ips.length) {
      setFact(udp, '已阻断 · 规则已核验', 'ok');
      udp.title = 'root 任务已核验运行中的 UDP 拒绝规则与 pf，实测无回包符合策略。';
    } else if (!p.stunChecked) {
      setFact(udp, '没探到', 'off');
      udp.title = '四个 STUN 节点都没回。一次超时不作结论，也不报警。';
    } else if (p.stunExposed && p.stunExposed.length) {
      setFact(udp, 'STUN 风险 · ' + p.stunExposed.join(' / '), 'warn');
      udp.title = '国内 STUN 节点回了这些地址，和当前出口基线不是同一个。' +
        '分流规则把国内域名放直连，节点回真实地址是「正确答案」；' +
        '使用同类节点的网页可能取得这些地址；是否实际形成 ICE 候选需要浏览器实测确认。' +
        '最省事的做法是拒掉 3478 / 5349 / 19302 的 UDP，不依赖代理组是否支持 UDP。';
    } else if (p.stunLeak) {
      setFact(udp, '分裂 · ' + ips.join(' / '), 'warn');
      udp.title = '境外节点给出了两个不同的出口地址，说明一部分 UDP 走了直连。';
    } else if (p.egressSeen && p.egressMask) {
      // 基线还在，只是等用户确认新出口。说成「无基线」会让人以为塔没扫过。
      setFact(udp, ips.join(' / ') + ' · 待确认', 'off');
      udp.title = '出口基线还在等确认，确认之前不拿它判 UDP 泄漏——换了节点还是真泄漏，这一步分不出来。';
    } else if (!p.towerData || !p.maskFresh || !p.egressMask) {
      // 没有基线时只能证明「STUN 有回包」，证明不了它和 HTTP 出口是同一条。
      // 给绿灯等于替一个没做的比对下结论。
      setFact(udp, ips.join(' / ') + ' · 无基线', 'off');
      udp.title = '没有可用的出口基线，只能确认 STUN 有回包，判断不了它是不是同一个出口。';
    } else {
      setFact(udp, ips.join(' / '), 'ok');
      udp.title = 'STUN 打回来的地址（含国内节点）都落在当前出口上。' +
        '国内节点走直连、回同一个地址，说明 UDP 也进了隧道。';
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

    // ---- Claude 出口 ----
    // Claude 自己的边缘节点看到的地址。只回答「claude.ai / claude.com 是不是
    // 从同一个出口看我们」，不进主判定。
    var fd = $('#f-domain');
    if (!exitReady) {
      setFact(fd, '出口不在，没查', 'off');
      fd.title = '只在出口在位时查：出口不在的时候发请求，等于先把真实地址送出去一次。';
    } else if (!p.domainChecked) {
      setFact(fd, '还没测', 'off');
      fd.title = '哨兵会按周期重测，和传输诊断共用出口判定。';
    } else {
      var dst = p.domainState === 'ok' ? 'ok' : p.domainState === 'warn' ? 'warn' : 'off';
      setFact(fd, p.domainLabel || '—', dst);
      fd.title = (p.domainDetail || '') + (p.domainAt ? '（' + age(p.domainAt) + '测的）' : '');
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
    // 所以这里最多给一个「打开设置与更新」，不在菜单栏里动手。
    var fu = $('#f-update');
    var up = p.update || {};
    var bu = $('#btn-update');
    if (!up.configured) {
      setFact(fu, '未配置', 'off');
      fu.title = '塔里还没有填更新源。打开魔塔 → 设置 → 自动更新。';
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
      hint.innerHTML = p.vmManaged ? '戒严：核验现有 mihomo、TUN、固定节点与 pf 断网保护后启动；不要求系统代理或全局模式。节点、规则或保护状态变化会结束本次使用。' : p.upstream
        ? '戒严 · 上游代理：准入改查边缘出口、HTTPS 传输、DNS、UDP 与时区证据，本机代理机制不作要求。巡检发现上游出口变化会请求退出（同出口节点切换无法识别），未响应时尝试强制终止。<b>不保证检查前没有联网</b>，未保存工作可能丢失。'
        : '戒严：先检查并启动；缺证据不放行。模式、节点、出口或关键证据变化会请求退出，未响应时尝试强制终止。<b>不保证检查前没有联网</b>，未保存工作可能丢失。';
      if (p.isVM && !p.upstream) {
        hint.innerHTML += '<br><br>检测到虚拟化环境：若流量由宿主机或网关接管（本机无需开代理），可开启下方「上游代理」。';
      }
    } else {
      hint.innerHTML = '瞭望：持续检测并提醒，不会终止 Claude。需要自动拦截时可切换「戒严」。';
    }

    // ---- 操作按钮 ----
    var login = $('#btn-login');
    login.classList.toggle('on', !!p.loginItem && !p.loginBroken);
    login.textContent = p.loginItem
      ? (p.loginBroken ? '自启待修' : '已开机自启')
      : '开机自启';

    var upstream = $('#btn-upstream');
    upstream.hidden = !!p.vmManaged;
    upstream.classList.toggle('on', !!p.upstream);
    upstream.textContent = p.upstream ? '上游代理 · 开' : '上游代理';

    var pause = $('#btn-pause');
    pause.textContent = p.paused || p.enabled === false ? '继续值守' : '暂停 30 分钟';

    document.querySelectorAll('.fact-group').forEach(function (group) {
      var counts = {ok:0,warn:0,bad:0,off:0};
      group.querySelectorAll('.facts li').forEach(function (row) {
        if (row.hidden) return;
        counts[row.dataset.st || 'off'] += 1;
        var action = row.querySelector('.fact-action');
        if (action) action.hidden = row.dataset.st !== 'warn' && row.dataset.st !== 'bad';
      });
      var summary = group.querySelector('.group-status');
      summary.dataset.st = counts.bad ? 'bad' : counts.warn ? 'warn' : 'off';
      var parts = [];
      if (counts.bad + counts.warn) parts.push((counts.bad + counts.warn) + ' 项需处理');
      if (counts.ok) parts.push(counts.ok + ' 项通过');
      if (counts.off) parts.push(counts.off + ' 项未确认');
      summary.textContent = parts.join(' · ');
      // 首次出现新异常才展开；用户手动折叠后，正常推送不会把它反复撑开。
      var issue = counts.bad ? 'bad' : counts.warn ? 'warn' : '';
      if (issue && group.dataset.issue !== issue) group.open = true;
      group.dataset.issue = issue;
    });

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
          : h.kind === 'notower' ? '缺基线'
          : h.kind === 'egress' ? '出口变更'
          : h.kind === 'kill' ? '终止 Claude'
          : h.kind === 'gate' ? '拦下启动'
          : h.kind === 'fixtz' ? '改时区'
          : h.kind;
        // kill 也用红色：它和 danger 是同一件事的两步，分成两种颜色反而看不懂。
        // takeover 同样归红：客户端在跑却没接管，流量这会儿是直连的。
        // gate 是最重的一步——连启动都不让，和 kill 同一个色。
        // dns / stun / notower 归到 gold：它们不是「断了」，是「规则没做全」。
        var cls = h.kind === 'kill' || h.kind === 'takeover' || h.kind === 'gate' ? 'danger'
          : h.kind === 'dns' || h.kind === 'stun' || h.kind === 'notower'
            || h.kind === 'egress' ? 'warn'
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
      if (lv === 1 && S.claude && Number(S.level) >= 2 && !confirm('切换为瞭望会结束本次戒严使用并退出 Claude，未保存内容可能丢失。继续？')) return;
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
  $('#btn-egress').addEventListener('click', function () { post({ action: 'confirm-egress' }); });

  document.querySelectorAll('[data-tool]').forEach(function (button) {
    button.addEventListener('click', function () { post({action: button.dataset.tool === 'dns' ? 'repair-dns' : 'repair-udp'}); });
  });
  $('#btn-open').addEventListener('click', function () { post({ action: 'opentower' }); });
  $('#btn-tower').addEventListener('click', function () { post({ action: 'opentower' }); });
  $('#btn-drift').addEventListener('click', function () { post({ action: 'opentower' }); });
  $('#btn-upstream').addEventListener('click', function () {
    if (!S.upstream && !confirm('上游代理模式用于虚拟机、路由器透明代理等「本机看不到代理机制」的环境。\n\n开启后戒严不再要求本机系统代理、TUN 与全局模式，改以 Claude 边缘出口、HTTPS 传输、DNS、UDP 与时区为准入证据。\n\n若本机其实需要开代理才能安全访问 Claude，请不要开启。确认开启？')) return;
    post({ action: 'upstream' });
  });
  $('#btn-relogin').addEventListener('click', function () { post({ action: 'login' }); });
  $('#btn-update').addEventListener('click', function () { post({ action: 'update' }); });
  $('#btn-login').addEventListener('click', function () { post({ action: 'login' }); });
  $('#btn-log').addEventListener('click', function () { post({ action: 'log' }); });
  // 改时区会弹系统密码框，那就是确认步骤本身，不再加一次二次点击
  $('#btn-fixtz').addEventListener('click', function () { post({ action: 'fixtz' }); });
  $('#btn-pause').addEventListener('click', function () {
    if (!S.paused && S.claude && Number(S.level) >= 2 && !confirm('暂停值守会先退出 Claude，未保存内容可能丢失。继续？')) return;
    post(S.paused || S.enabled === false ? { action: 'resume' } : { action: 'pause', minutes: 30 });
  });
  $('#btn-quit').addEventListener('click', function () {
    if (S.claude && Number(S.level) >= 2 && !confirm('退出哨兵会先退出本次戒严使用的 Claude，未保存内容可能丢失。继续？')) return;
    post({ action: 'quit' });
  });

  window.SHIELD = { update: render };
  $('#btn-start').addEventListener('click', function () { if (!this.disabled) post({action: 'session-start'}); });
  $('#btn-session-end').addEventListener('click', function () {
    if (confirm('结束本次使用会退出 Claude，未保存内容可能丢失。确认继续？')) post({action: 'session-end'});
  });
})();
