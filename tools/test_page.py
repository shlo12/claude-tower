#!/usr/bin/env python3
"""页面冒烟测试：真开一个 Chrome，确认页面能起来、接口能通、按钮不发 403。

    python3 tools/test_page.py

用 CDP 直接看 console 报错和网络状态，比截图更能定位问题。
"""

from __future__ import annotations

import json
import base64
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP_PORT = 8792
CDP_PORT = 9333
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class CDP:
    """极简 CDP 客户端：只用到 Page / Runtime / Network 三个域。"""

    def __init__(self, ws_url: str):
        self.url = ws_url
        self.sock = socket.create_connection(("127.0.0.1", CDP_PORT), timeout=30)
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        path = ws_url.split(f"127.0.0.1:{CDP_PORT}", 1)[1]
        req = (
            f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{CDP_PORT}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.sock.recv(4096)
        self._buf = buf.split(b"\r\n\r\n", 1)[1]
        self._id = 0
        self.events: list[dict] = []

    def _recv_exact(self, n: int) -> bytes:
        out = self._buf
        while len(out) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket 断了")
            out += chunk
        self._buf = out[n:]
        return out[:n]

    def _recv_frame(self) -> dict:
        head = self._recv_exact(2)
        ln = head[1] & 0x7F
        if ln == 126:
            ln = int.from_bytes(self._recv_exact(2), "big")
        elif ln == 127:
            ln = int.from_bytes(self._recv_exact(8), "big")
        payload = self._recv_exact(ln)
        return json.loads(payload.decode("utf-8"))

    def call(self, method: str, params=None, timeout=30):
        self._id += 1
        mid = self._id
        msg = json.dumps({"id": mid, "method": method, "params": params or {}})
        data = msg.encode()
        mask = b"\x00\x00\x00\x00"
        header = bytearray([0x81])
        ln = len(data)
        if ln < 126:
            header.append(0x80 | ln)
        elif ln < 65536:
            header.append(0x80 | 126)
            header += ln.to_bytes(2, "big")
        else:
            header.append(0x80 | 127)
            header += ln.to_bytes(8, "big")
        self.sock.sendall(bytes(header) + mask + data)

        deadline = time.time() + timeout
        while time.time() < deadline:
            frame = self._recv_frame()
            if frame.get("id") == mid:
                return frame
            if "method" in frame:
                self.events.append(frame)
        raise TimeoutError(method)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def main() -> int:
    # 隔离 HOME：声明已读、运行时目录都写在 HOME 下，不能让测试碰真实环境
    home = Path(tempfile.mkdtemp(prefix="ccclean-page-"))
    # 造一份最小 FlClash 配置：只用来验分流修复卡片的状态/预览，不碰真配置
    clash = home / "Library" / "Application Support" / "com.follow.clash"
    clash.mkdir(parents=True)
    (clash / "config.yaml").write_text(
        "mixed-port: 7890\n"
        "proxy-groups:\n  - name: Ai+\n    type: select\n    proxies: [DIRECT]\n"
        "rules:\n  - RULE-SET,Claude,Ai+\n  - MATCH,DIRECT\n",
        encoding="utf-8",
    )
    con = sqlite3.connect(clash / "database.sqlite")
    try:
        con.execute(
            'create table rules (id integer primary key, profile_id integer, '
            'rule_action text, content text, rule_target text, rule_provider text, '
            'sub_rule text, no_resolve integer, src integer, "order" text)'
        )
        con.commit()
    finally:
        con.close()
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    app = subprocess.Popen(
        [sys.executable, str(ROOT / "app.py"), "--port", str(APP_PORT), "--no-open"],
        cwd=str(ROOT), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    profile = Path("/tmp/ccclean-chrome-profile")
    subprocess.run(["rm", "-rf", str(profile)], check=False)
    chrome = subprocess.Popen(
        [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--in-process-gpu",
         "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check",
         f"--remote-debugging-port={CDP_PORT}", f"--user-data-dir={profile}",
         "--window-size=1440,960", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    cdp = None
    try:
        for _ in range(100):
            try:
                raw = OPENER.open(f"http://127.0.0.1:{CDP_PORT}/json/list", timeout=2).read()
                tabs = json.loads(raw)
                page = next((t for t in tabs if t.get("type") == "page"), None)
                if page:
                    cdp = CDP(page["webSocketDebuggerUrl"])
                    break
            except Exception:
                pass
            time.sleep(0.2)
        if not cdp:
            print("✗ Chrome 没起来")
            return 1

        cdp.call("Page.enable")
        cdp.call("Runtime.enable")
        cdp.call("Network.enable")

        def evaluate(expr):
            r = cdp.call("Runtime.evaluate", {"expression": expr, "awaitPromise": True,
                                              "returnByValue": True})
            return r.get("result", {}).get("result", {}).get("value")

        def wait_for(expr, timeout=25.0):
            """等到条件为真再往下走，不要等固定秒数。

            冷启动时 networksetup 和首轮扫描都可能慢上几秒，固定 sleep 会把
            「还没渲染完」记成失败。假失败比真失败更坏：真坏了会被当成
            「又是那个 flaky」，没人再去看。"""
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    if evaluate(expr):
                        return True
                except Exception:
                    pass
                time.sleep(0.15)
            return False

        def goto(url, ready, label):
            cdp.call("Page.navigate", {"url": url})
            ok = wait_for(ready)
            if not ok:
                print(f"  ! 等待超时：{label}（后面的断言会跟着失败）")
            # 让收尾的 console / 网络事件落地，否则错误会被漏收
            time.sleep(0.4)
            return ok

        url = f"http://127.0.0.1:{APP_PORT}/"
        READY = ("!!(window.CC && window.CC.api && window.Tower && window.Tower.reload "
                 "&& ((document.querySelector('#t-ver')||{}).textContent||'').trim())")
        goto(url, READY, "首页就绪")

        # 收集 console 错误与失败的请求
        js_errors, failed = [], []
        for ev in cdp.events:
            m = ev.get("method")
            if m == "Runtime.exceptionThrown":
                js_errors.append(ev["params"]["exceptionDetails"].get("text", "?"))
            if m == "Network.responseReceived":
                r = ev["params"]["response"]
                if r["status"] >= 400:
                    failed.append(f'{r["status"]} {r["url"]}')
            if m == "Runtime.consoleAPICalled" and ev["params"]["type"] == "error":
                js_errors.append(str(ev["params"]["args"])[:160])

        checks = []
        checks.append(("页面标题正确", "CC Tower" in (evaluate("document.title") or "")))
        checks.append(("令牌已注入", len(evaluate(
            "(document.querySelector('meta[name=cc-token]')||{}).content||''") or "") >= 32))
        checks.append(("window.CC 就绪", evaluate("!!(window.CC && window.CC.api)")))
        checks.append(("window.Tower 就绪", evaluate("!!window.Tower")))
        checks.append(("四个统一主入口", evaluate("document.querySelectorAll('.primary-tabs .tab').length") == 4))
        checks.append(("默认进魔塔体检而非游戏遮罩", evaluate("document.querySelector('#panel-tower').classList.contains('active') && document.querySelector('#title').hidden") is True))
        checks.append(("守护台不再重复出现在主窗口", evaluate("document.querySelector('#panel-home') === null") is True))
        checks.append(("更新及接口移到设置", evaluate("!!document.querySelector('#panel-settings #update-card') && !!document.querySelector('#panel-settings #sessionapi-card')") is True))
        checks.append(("操作记录移到记录页", evaluate("!!document.querySelector('#panel-records #history-card')") is True))

        # 导航只剩一层：二级只在魔塔体检下出现，另外三个一级页一页到底。
        evaluate("window.CC.setUnlocked(true); window.CC.switchTab('tower'); 'ok'")
        nav = evaluate("""(() => {
          const subs = [...document.querySelectorAll('.sub-tabs')];
          return {
            groups: subs.map(n => n.dataset.group),
            shown: subs.filter(n => !n.hidden).map(n => n.dataset.group),
            tower: document.querySelectorAll('.sub-tabs[data-group=tower] .tab').length,
            inNav: !!document.querySelector('.sub-tabs #open-game'),
            inTop: !!document.querySelector('.topbar #open-game'),
          };
        })()""") or {}
        checks.append(("二级导航只剩魔塔体检一组", nav.get('groups') == ['tower'], str(nav.get('groups'))))
        checks.append(("魔塔体检二级收成三项", nav.get('tower') == 3, str(nav.get('tower'))))
        checks.append(("标题画面按钮在顶栏、不在页签行",
                       nav.get('inTop') is True and nav.get('inNav') is False))

        # 合并页：一页两种看法，切视图不动页签。
        seg = evaluate("""(() => {
          window.CC.switchTab('settle');
          const before = {
            settle: !document.querySelector('#view-settle').hidden,
            findings: document.querySelector('#view-findings').hidden,
            tab: document.querySelector('.sub-tabs [data-tab=settle]').classList.contains('active'),
            panel: document.querySelector('#panel-results').classList.contains('active'),
          };
          document.querySelector('.viewseg [data-view=findings]').click();
          const after = {
            settle: document.querySelector('#view-settle').hidden,
            findings: !document.querySelector('#view-findings').hidden,
            tab: document.querySelector('.sub-tabs [data-tab=settle]').classList.contains('active'),
            seg: document.querySelector('.viewseg [data-view=findings]').classList.contains('on'),
            panel: document.querySelector('#panel-results').classList.contains('active'),
          };
          return {before, after};
        })()""") or {}
        before = seg.get('before') or {}
        after = seg.get('after') or {}
        checks.append(("结算与详情同属一页，默认按层",
                       before.get('panel') is True and before.get('settle') is True
                       and before.get('findings') is True and before.get('tab') is True))
        checks.append(("切到按类不换页签，只换视图",
                       after.get('panel') is True and after.get('findings') is True
                       and after.get('settle') is True and after.get('tab') is True
                       and after.get('seg') is True))

        # 记录三页、修复两页同理：页内分段，不再占一条菜单行。
        merged = evaluate("""(() => {
          window.CC.switchTab('records');
          const r1 = !document.querySelector('#view-records').hidden
                  && document.querySelector('#view-cruise').hidden
                  && document.querySelector('#view-board').hidden;
          document.querySelector('.viewseg [data-view=board]').click();
          const r2 = !document.querySelector('#view-board').hidden
                  && document.querySelector('#view-records').hidden
                  && document.querySelector('#panel-records').classList.contains('active')
                  && !document.querySelector('.sub-tabs[data-group=records]');
          window.CC.switchTab('isolation');
          const p1 = !document.querySelector('#view-isolation').hidden
                  && document.querySelector('#view-privacy').hidden
                  && document.querySelector('#panel-privacy').classList.contains('active')
                  && !document.querySelector('.sub-tabs[data-group=privacy]');
          window.CC.switchTab('tower');
          return {r1, r2, p1};
        })()""") or {}
        checks.append(("记录三页合在一页里分段切换", merged.get('r1') is True and merged.get('r2') is True))
        checks.append(("配置隔离并进修复页", merged.get('p1') is True))
        # 两边都没有记录时只留一句话：两个「暂无」各占一张卡，看着像没加载出来。
        # 直接摆好两种列表再调同步函数，不依赖这台机器上真有没有历史。
        empty = evaluate("""(() => {
          window.CC.switchTab('records');
          const g = document.querySelector('#guard-events'), h = document.querySelector('#history-list');
          g.innerHTML = '<li class="hist-empty">x</li>';
          h.innerHTML = '<li class="hist-empty">x</li>';
          syncRecordsEmpty();
          const line = document.querySelector('#records-empty');
          const on = {
            line: !line.hidden,
            guard: getComputedStyle(document.querySelector('#guard-card')).display === 'none',
            hist: getComputedStyle(document.querySelector('#history-card')).display === 'none'
          };
          h.innerHTML = '<li class="hist-item">x</li>';
          syncRecordsEmpty();
          const back = line.hidden
            && getComputedStyle(document.querySelector('#guard-card')).display !== 'none';
          h.innerHTML = '';
          syncRecordsEmpty();
          return {on, back};
        })()""") or {}
        on = empty.get('on') or {}
        checks.append(("记录页两边都空时并成一句",
                       on.get('line') is True and on.get('guard') is True and on.get('hist') is True))
        checks.append(("任一边有记录就恢复两张卡", empty.get('back') is True))
        # 说明默认收起：正文只留一行结论，机制解释折进「说明」。
        checks.append(("卡片说明默认收起", evaluate(
            "[...document.querySelectorAll('.more')].every(d => !d.open)"
            " && document.querySelectorAll('.more').length >= 8") is True))
        evaluate("window.CC.switchTab('tower'); 'ok'")
        # 启动/结束会话已经跟着守护台回到菜单栏面板，主窗口只剩设置页那几个开关。
        guard_ui = evaluate("""(async()=>{
          const originalFetch=window.fetch, originalConfirm=window.confirm;
          const calls=[];
          let state={ok:true,supported:true,running:true,fresh:true,enabled:true,paused:false,level:2,state:'watch',message:'测试',live:{age:1},hits:[],login:'loaded'};
          window.fetch=async(url,opts)=>String(url)==='/api/control' ? {ok:true,status:200,json:async()=>{
            if(opts?.method==='POST'){calls.push(JSON.parse(opts.body));return {ok:true,message:'已接收'};}
            return state;
          }} : originalFetch(url,opts);
          try {
            await Guard.refresh();
            const pauseReady=!document.querySelector('#guard-pause').disabled;
            window.confirm=()=>false;document.querySelector('#guard-pause').click();
            await new Promise(r=>setTimeout(r,120));
            const canceled=calls.length;
            window.confirm=()=>true;document.querySelector('#guard-pause').click();
            await new Promise(r=>setTimeout(r,160));
            return {pauseReady,canceled,count:calls.length,action:calls[0]?.action,confirmed:calls[0]?.confirm};
          } finally {window.fetch=originalFetch;window.confirm=originalConfirm;await Guard.refresh();}
        })()""") or {}
        checks.append(("设置页可暂停值守，取消确认则不发送", guard_ui.get('pauseReady') and guard_ui.get('canceled') == 0))
        checks.append(("确认后只发送一条 pause 指令", guard_ui.get('count') == 1 and guard_ui.get('action') == 'pause' and guard_ui.get('confirmed') is True))
        # 版本号别在测试里写死：从 app.py 里读，改版本时才不会连累这一项
        m_ver = re.search(r'^VERSION\s*=\s*"([^"]+)"', (ROOT / "app.py").read_text(encoding="utf-8"), re.M)
        want_ver = "v" + (m_ver.group(1) if m_ver else "?")
        checks.append(("版本号取自后端", (evaluate(
            "(document.querySelector('#t-ver')||{}).textContent||''").strip() or "") == want_ver,
            want_ver))
        checks.append(("魔塔数据已加载", evaluate("!!(window.Tower && window.Tower.reload)")))

        # 真打一次接口：模拟前端带令牌
        probe = evaluate("""
          (async () => {
            const r = await fetch('/api/backups', { headers: window.CC.ccHeaders() });
            return r.status + '|' + ((await r.json()).backups || []).length;
          })()
        """)
        checks.append(("带令牌调 /api/backups 成功", str(probe).startswith("200|")))

        # 免责声明：内容得对得上实现，版本门禁得真的生效
        notice_text = evaluate("(document.querySelector('#nt-body')||{}).innerText||''") or ""
        checks.append(("声明写明会改本机", "会真的改你的机器" in notice_text))
        checks.append(("声明列出钥匙串不可回滚", "没有备份" in notice_text and "钥匙串" in notice_text))
        checks.append(("声明明确敏感内容不留副本且不可还原", "不保留副本" in notice_text and "无法还原" in notice_text))
        checks.append(("声明不再自称只读检查器", "只读的本机环境检查器" not in notice_text))
        first_h3 = evaluate(
            "(document.querySelector('#nt-body section:first-child h3')||{}).innerText||''") or ""
        first_cls = evaluate(
            "(document.querySelector('#nt-body section:first-child')||{}).className||''") or ""
        checks.append(("『因果不可观测』排在声明第一条",
                       "因果不可观测" in first_h3 and "nt-key" in first_cls))

        # 老版本号的「已读」不算数：必须重弹
        evaluate("localStorage.setItem('cc.notice.v1','0.0.0'); 'ok'")
        goto(url, READY + " && !document.querySelector('#notice').hidden",
             "旧版本已读 → 重弹声明")
        checks.append(("旧版本的已读记录会重弹声明",
                       evaluate("!document.querySelector('#notice').hidden") is True))

        # 当前版本号的「已读」算数：不该再打扰
        evaluate("localStorage.setItem('cc.notice.v1',"
                 "(document.querySelector('meta[name=cc-version]')||{}).content||''); 'ok'")
        goto(url, READY, "当前版本已读 → 不打扰")
        # 这里等的是「不该发生的事」，没法用条件等待；多等一会儿只会更严格
        time.sleep(1.0)
        checks.append(("当前版本的已读记录不再重弹",
                       evaluate("document.querySelector('#notice').hidden") is True))

        evaluate("window.CC.switchTab('tower'); 'ok'")
        wait_for("document.querySelector('#panel-tower').classList.contains('active')")
        shot = cdp.call('Page.captureScreenshot', {'format':'png'}).get('result', {})
        if shot.get('data'):
            Path('/tmp/unified-tower.png').write_bytes(base64.b64decode(shot['data']))

        # 备份与还原卡片要能渲染出来（空列表也得有空状态，不能白屏）
        # 新用户尚未闯关时魔镜会被门禁挡住；只在本页模拟解锁，不写后端进度。
        evaluate("window.CC.setUnlocked(true); document.querySelector('.viewseg [data-view=findings]')"
                 " && document.querySelector('.viewseg [data-view=findings]').click()")
        wait_for("((document.querySelector('#restore-list')||{}).innerHTML||'').trim().length > 0")
        box = evaluate("(document.querySelector('#restore-list')||{}).innerHTML||''") or ""
        checks.append(("备份卡片有内容（列表或空状态）", len(box.strip()) > 0, box[:60]))
        checks.append(("备份列表能读到接口", "读取失败" not in box, box[:120]))
        checks.append(("全量快照已改为安全快照", evaluate(
            "document.querySelector('#snapshot-make').closest('.card').querySelector('h3').textContent") == "安全快照"))
        checks.append(("清单说明不冒充敏感内容备份", "不留副本" in box and "不可还原" in box))

        # 浏览器侧 WebRTC 那一行必须带「实测」按钮：2-8 关卡承诺了要测，
        # 界面上得真的能点。只验渲染与函数挂载，不点它——点了会真发 ICE
        # 并往 ~/.ccclean 写一份结果，那是用户的真实数据。
        # 首轮扫描是异步的（塔要先跑一遍探针），这里等它真的落地再注入。
        # 不等就会把「还没扫完」记成「按钮没渲染」，那是假失败。
        wait_for("!!(window.CC.state && window.CC.state.scan"
                 " && Array.isArray(window.CC.state.scan.items))", timeout=45.0)
        probe_ui = evaluate("""
          (() => {
            const s = window.CC.state.scan;
            if (!s || !Array.isArray(s.items)) return {ok:false, why:'没有扫描结果'};
            s.items.push({id:'net.webrtc_browser', category:'network', title:'探针按钮演示',
                          severity:'info', detail:'', evidence:[], advice:'', fix:null,
                          tags:[], probe:'webrtc'});
            window.CC.setScan(s);
            const btn = document.querySelector('[data-probe="webrtc"]');
            return {ok: !!btn, text: btn ? btn.textContent.trim() : '',
                    fn: typeof window.CC.runWebrtcProbe === 'function'};
          })()
        """) or {}
        checks.append(("浏览器实测按钮已渲染", probe_ui.get("ok") is True, str(probe_ui)[:80]))
        checks.append(("实测入口挂在 CC 上", probe_ui.get("fn") is True))
        checks.append(("按钮文案说清在哪儿测",
                       "浏览器" in (probe_ui.get("text") or ""), probe_ui.get("text") or ""))

        # 仅模拟预览响应来验证不可逆提示；不调用真实清理或扫描。
        preview = evaluate("""
          (async () => {
            const originalFetch = window.fetch;
            const originalScan = window.CC.state.scan;
            const item = {id:'retention-preview-test',title:'缓存清理演示',fix:{kind:'trash'}};
            window.fetch = async (url, options) => String(url) === '/api/preview'
              ? new Response(JSON.stringify({plan:{ops:[{id:item.id,title:'直接删除缓存（演示）',
                  display:'~/.claude/debug',retention:'no-copy',risk:'不备份、不进废纸篓，删除后无法还原'}],
                  skipped:[],warnings:[],totalFiles:1,totalBytes:64},running:[]}),
                  {headers:{'Content-Type':'application/json'}})
              : originalFetch(url, options);
            window.CC.state.scan = {items:[item]};
            window.CC.selectForClean([item.id]);
            await new Promise(resolve => setTimeout(resolve, 150));
            const result = {text:document.querySelector('#modal-list').innerText,
                            disabled:document.querySelector('#modal-go').disabled};
            window.fetch = originalFetch;
            window.CC.state.scan = originalScan;
            window.CC.state.sel.clear();
            document.querySelector('#modal').classList.remove('show');
            window.CC.updatePickBar();
            return result;
          })()
        """) or {}
        checks.append(("清理预览展示不留副本及不可还原", "不留副本 · 不可还原" in preview.get("text", "")))
        checks.append(("不可逆清理仍需输入 CLEAN", preview.get("disabled") is True))

        # 对齐使用假出口，仅验证选择与预览，绝不执行设置写入。
        align_ui = evaluate("""(async () => {
          const original = window.fetch;
          const keys = ['country','timezone','locale','language'];
          window.fetch = async (url, opts) => String(url) === '/api/align'
            ? new Response(JSON.stringify({supported:true,canApply:true,canRestore:false,egress:{country:'US'},
                rows:keys.map(key=>({key,label:key,current:'old',target:key==='language'?'en-US':'target',needed:true,
                  needsAdmin:key==='timezone',requiresOptIn:key==='language'}))}), {headers:{'Content-Type':'application/json'}})
            : original(url, opts);
          try {
            window.CC.switchTab('privacy');
            for(let i=0;i<100 && !document.querySelector('#align-rows input[data-key=language]');i++)
              await new Promise(r=>setTimeout(r,20));
            const picked = document.querySelectorAll('#align-rows input:checked').length;
            const lang = document.querySelector('#align-rows input[data-key=language]');
            lang.click(); document.querySelector('#align-apply').click();
            const text = document.querySelector('#align-plan').textContent;
            document.querySelector('#align-rows input[data-key=language]').click();
            return {picked,text,invalidated:document.querySelector('#align-preview').hidden};
          } finally {window.fetch=original;}
        })()""") or {}
        checks.append(("对齐各项默认不勾选", align_ui.get("picked") == 0))
        checks.append(("首选语言可单独预览", "en-US" in align_ui.get("text", "")))
        checks.append(("改变勾选作废旧对齐预览", align_ui.get("invalidated") is True))

        # 新本机接口卡片：HTTP 完全打桩，确认/取消都不会改真实客户端。
        session_ui = evaluate("""(async () => {
          const originalFetch = window.fetch, originalConfirm = window.confirm;
          const requests = [];
          window.fetch = async (url, opts) => String(url) === '/api/sessionapi'
            ? (opts && opts.method === 'POST'
              ? (requests.push(opts), new Response(JSON.stringify({ok:true,message:'fixture-only'}), {headers:{'Content-Type':'application/json'}}))
              : new Response(JSON.stringify({ok:true,token:'session-fixture',canApply:true,canUndo:false,message:'fixture'}),{headers:{'Content-Type':'application/json'}}))
            : originalFetch(url,opts);
          try {
            await refreshSessionApi();
            window.confirm = () => false;
            await changeSessionApi('apply');
            const canceled = requests.length === 0;
            window.confirm = () => true;
            await changeSessionApi('apply');
            return {canceled, count:requests.length, token:requests[0].headers['X-CClean-Privacy-Token'], confirmed:JSON.parse(requests[0].body).confirm};
          } finally {window.fetch=originalFetch;window.confirm=originalConfirm;}
        })()""") or {}
        checks.append(("本机监测接口预览取消不写入", session_ui.get('canceled') is True))
        checks.append(("本机监测接口独立令牌与确认", session_ui.get('count') == 1 and session_ui.get('token') == 'session-fixture' and session_ui.get('confirmed') is True))

        # IPv6 出口：只验提示与确认链路，绝不点「确认」（那会真的调 networksetup）
        evaluate("window.CC.switchTab('privacy'); 'ok'")
        # 不能等「文本非空」：#ipv6-status 的初始文案就是「读取 IPv6 状态…」，
        # 非空永远成立，等于没等。要等的是 ipv6State 真的被填上。
        wait_for("!!(typeof ipv6State !== 'undefined' && ipv6State && ipv6State.services)")
        checks.append(("IPv6 卡片存在", evaluate("!!document.querySelector('#ipv6-card')")))
        ipv6_status = evaluate(
            "(document.querySelector('#ipv6-status')||{}).textContent||''") or ""
        checks.append(("IPv6 状态读到 Wi-Fi 服务", "当前 IPv6" in ipv6_status and "只改 Wi-Fi" in ipv6_status,
                       ipv6_status[:100]))
        # 这台机器可能已经把 Wi-Fi 的 IPv6 关掉了（本工具关过或用户手动关）。
        # 那种状态下按钮本来就该禁用——测试不能为了让按钮可点去改用户的系统设置。
        ipv6_auto = evaluate(
            "((typeof ipv6State !== 'undefined' && ipv6State && ipv6State.automatic) || []).length") or 0
        ipv6_off_disabled = evaluate(
            "document.querySelector('#ipv6-off').disabled") is True
        if ipv6_auto:
            checks.append(("IPv6 关闭按钮可用", not ipv6_off_disabled))
            evaluate("document.querySelector('#ipv6-off').click(); 'ok'")
            wait_for("((document.querySelector('#ipv6-services')||{}).textContent||'').includes('→ Off')")
            ipv6_rows = evaluate(
                "(document.querySelector('#ipv6-services')||{}).textContent||''") or ""
            checks.append(("IPv6 预览列出服务与目标", "→ Off" in ipv6_rows, ipv6_rows[:80]))
            checks.append(("未勾选影响确认时不能执行", evaluate(
                "document.querySelector('#ipv6-confirm').disabled") is True))
            evaluate("""(() => {
              const c = document.querySelector('#ipv6-ack');
              c.checked = true;
              c.dispatchEvent(new Event('change'));
              return 'ok';
            })()""")
            wait_for("document.querySelector('#ipv6-confirm').disabled === false")
            checks.append(("勾选影响确认后才能执行", evaluate(
                "document.querySelector('#ipv6-confirm').disabled") is False))
            evaluate("document.querySelector('#ipv6-cancel').click(); 'ok'")
        else:
            checks.append(("IPv6 已关闭时关闭按钮禁用", ipv6_off_disabled))
            checks.append(("IPv6 已关闭时不出预览", evaluate(
                "document.querySelector('#ipv6-preview').hidden") is True))

        # 自动更新：隔离 HOME 下没有配置仓库，应停在「未配置」且不露下载按钮。
        # 光检查 hidden 属性不够——.tool-row 的 display:flex 会把它盖掉，
        # 必须看计算后的样式。
        wait_for("((document.querySelector('#update-status')||{}).textContent||'')"
                 ".includes('没有填写更新源')")
        checks.append(("更新卡片未配置时徽标正确", evaluate(
            "document.querySelector('#update-badge').textContent") == "未配置"))
        checks.append(("未配置时下载按钮不显示", evaluate(
            "getComputedStyle(document.querySelector('#update-actions')).display") == "none"))

        # 卸载器：只验清单渲染与「打字确认」这道闸门，绝不点执行。
        # 点下去会真的把应用包和状态目录移进废纸篓——那是用户的数据。
        wait_for("((document.querySelector('#uninstall-list')||{}).textContent||'')"
                 ".includes('应用')", timeout=40.0)
        un_items = evaluate(
            "(document.querySelectorAll('#uninstall-list .un-item')||[]).length") or 0
        checks.append(("卸载清单渲染出条目", un_items >= 5, f"{un_items} 项"))
        checks.append(("卸载清单含本程序自身",
                       "CC Tower" in (evaluate(
                           "(document.querySelector('#uninstall-list')||{}).textContent||''") or "")))
        checks.append(("未输入确认串时执行按钮禁用", evaluate(
            "document.querySelector('#uninstall-go').disabled") is True))
        evaluate("""(() => {
          const el = document.querySelector('#uninstall-confirm');
          el.value = 'UNINSTALL';
          el.dispatchEvent(new Event('input'));
          return 'ok';
        })()""")
        checks.append(("输入 UNINSTALL 后执行按钮可用", evaluate(
            "document.querySelector('#uninstall-go').disabled") is False))
        evaluate("""(() => {
          const el = document.querySelector('#uninstall-confirm');
          el.value = 'UNINSTAL';
          el.dispatchEvent(new Event('input'));
          return 'ok';
        })()""")
        checks.append(("输错一个字母按钮又变回禁用", evaluate(
            "document.querySelector('#uninstall-go').disabled") is True))
        # 收尾：把确认串清掉，别把页面留在「一按就卸」的状态
        evaluate("document.querySelector('#uninstall-confirm').value = ''; 'ok'")

        # 出口国家预期：隔离 HOME 下真的读写一次，验证保存/清除闭环
        wait_for("!((document.querySelector('#netcfg-status')||{}).textContent||'')"
                 ".includes('读取预期国家')")
        checks.append(("国家预期卡片存在", evaluate("!!document.querySelector('#netcfg-card')")))
        checks.append(("未设置时徽标为未设置", evaluate(
            "document.querySelector('#netcfg-badge').textContent") == "未设置"))
        netcfg_status = evaluate(
            "(document.querySelector('#netcfg-status')||{}).textContent||''") or ""
        checks.append(("未设置时不判断国家", "不会判断出口国家" in netcfg_status,
                       netcfg_status[:100]))
        evaluate("""(() => {
          document.querySelector('#netcfg-country').value = 'us';
          document.querySelector('#netcfg-save').click();
          return 'ok';
        })()""")
        wait_for("document.querySelector('#netcfg-badge').textContent === '已设 US'")
        netcfg_saved = evaluate("""({
          badge: document.querySelector('#netcfg-badge').textContent,
          status: document.querySelector('#netcfg-status').textContent,
          country: document.querySelector('#netcfg-country').value})""") or {}
        checks.append(("保存小写代码会规范成大写", netcfg_saved.get("badge") == "已设 US",
                       str(netcfg_saved)))
        checks.append(("保存后说明不会再自动改地区",
                       "不会自动改地区" in netcfg_saved.get("status", ""),
                       netcfg_saved.get("status", "")[:100]))
        evaluate("document.querySelector('#netcfg-clear').click(); 'ok'")
        wait_for("document.querySelector('#netcfg-badge').textContent === '未设置'")
        netcfg_cleared = evaluate("""({
          badge: document.querySelector('#netcfg-badge').textContent,
          status: document.querySelector('#netcfg-status').textContent})""") or {}
        checks.append(("清除后回到未设置", netcfg_cleared.get("badge") == "未设置",
                       str(netcfg_cleared)))
        checks.append(("清除后恢复不判断", "不会判断出口国家" in netcfg_cleared.get("status", ""),
                       netcfg_cleared.get("status", "")[:100]))

        # 终端代理变量：只看预览，绝不点「确认」（会真的写 .zshrc）
        checks.append(("终端代理卡片存在", evaluate("!!document.querySelector('#shellproxy-card')")))
        sp_status = evaluate(
            "(document.querySelector('#shellproxy-status')||{}).textContent||''") or ""
        checks.append(("终端代理读到启动文件", "启动文件：" in sp_status, sp_status[:120]))
        sp_can = evaluate("!document.querySelector('#shellproxy-apply').disabled") is True
        if sp_can:
            checks.append(("终端代理预览按钮可用", True))
            evaluate("""(() => {
              const el = document.querySelector('#shellproxy-port');
              el.value = '7890';
              el.dispatchEvent(new Event('input', { bubbles: true }));
              document.querySelector('#shellproxy-apply').click();
              return 'ok';
            })()""")
            wait_for("!document.querySelector('#shellproxy-preview').hidden")
            sp_block = evaluate(
                "(document.querySelector('#shellproxy-block')||{}).textContent||''") or ""
            checks.append(("终端代理预览显示要写的块",
                           "ccclean terminal proxy" in sp_block, sp_block[:100]))
            checks.append(("预览里带着端口", "127.0.0.1:7890" in sp_block, sp_block[:100]))
            checks.append(("预览说明会先测端口",
                           "测不通就不写" in (evaluate(
                               "(document.querySelector('#shellproxy-preview-text')||{}).textContent||''") or "")))
            evaluate("document.querySelector('#shellproxy-cancel').click(); 'ok'")
            checks.append(("取消后终端代理预览收起", evaluate(
                "document.querySelector('#shellproxy-preview').hidden") is True))
        else:
            # 已经有别人的代理变量时不该给写入按钮
            checks.append(("终端代理：有冲突时不给写", "已经有代理变量" in sp_status,
                           sp_status[:120]))

        # 区域格式：只看状态和预览，绝不点「确认」（会真的改系统 AppleLocale）
        checks.append(("区域格式卡片存在", evaluate("!!document.querySelector('#region-card')")))
        region_status = evaluate(
            "(document.querySelector('#region-status')||{}).textContent||''") or ""
        checks.append(("区域格式读到当前值", "当前：" in region_status, region_status[:100]))
        evaluate("""(() => {
          const el = document.querySelector('#region-target');
          el.value = 'JP';
          el.dispatchEvent(new Event('input', { bubbles: true }));
          document.querySelector('#region-apply').click();
          return 'ok';
        })()""")
        wait_for("!document.querySelector('#region-preview').hidden")
        region_preview = evaluate(
            "(document.querySelector('#region-preview-text')||{}).textContent||''") or ""
        checks.append(("区域格式预览给出要写的值", "ja_JP" in region_preview,
                       region_preview[:120]))
        checks.append(("区域格式预览说明只改一个键",
                       "不动系统语言和时区" in region_preview, region_preview[:120]))
        evaluate("document.querySelector('#region-cancel').click(); 'ok'")
        checks.append(("取消后预览收起", evaluate(
            "document.querySelector('#region-preview').hidden") is True))

        # 分流修复：只看状态和预览，绝不点「确认」（会退出并重开 FlClash）
        checks.append(("分流修复卡片存在", evaluate("!!document.querySelector('#proxyfix-card')")))
        proxy_status = evaluate(
            "(document.querySelector('#proxyfix-status')||{}).textContent||''") or ""
        checks.append(("分流修复读到 FlClash", "FlClash" in proxy_status and "已覆盖" in proxy_status,
                       proxy_status[:100]))
        can_preview = evaluate(
            "!document.querySelector('#proxyfix-apply').disabled") is True
        if can_preview:
            checks.append(("有缺规则时预览按钮可用", True))
            evaluate("document.querySelector('#proxyfix-apply').click(); 'ok'")
            wait_for("((document.querySelector('#proxyfix-rules')||{}).textContent||'')"
                     ".includes('DST-PORT,3478')")
            proxy_rules = evaluate(
                "(document.querySelector('#proxyfix-rules')||{}).textContent||''") or ""
            checks.append(("分流预览列出待写规则", "DST-PORT,3478" in proxy_rules,
                           proxy_rules[:100]))
            checks.append(("预览后确认按钮可点", evaluate(
                "document.querySelector('#proxyfix-confirm').disabled") is False))
            evaluate("document.querySelector('#proxyfix-cancel').click(); 'ok'")

            # 端口策略换成「直接拒绝」，预览里的规则文本必须跟着变——
            # 预览和真正写下去的东西不是一回事的话，这个确认就没有意义了。
            evaluate("""
              (() => {
                const sel = document.querySelector('#proxyfix-port');
                sel.value = 'reject';
                sel.dispatchEvent(new Event('change', { bubbles: true }));
                return 'ok';
              })()
            """)
            wait_for("((document.querySelector('#proxyfix-status')||{}).textContent||'')"
                     ".includes('直接拒绝')")
            port_status = evaluate(
                "(document.querySelector('#proxyfix-status')||{}).textContent||''") or ""
            checks.append(("端口策略可切到直接拒绝", "直接拒绝" in port_status,
                           port_status[:100]))
            if evaluate("!document.querySelector('#proxyfix-apply').disabled") is True:
                evaluate("document.querySelector('#proxyfix-apply').click(); 'ok'")
                wait_for("((document.querySelector('#proxyfix-rules')||{}).textContent||'')"
                         ".includes('DST-PORT,3478,REJECT')")
                reject_rules = evaluate(
                    "(document.querySelector('#proxyfix-rules')||{}).textContent||''") or ""
                checks.append(("拒绝模式下预览写成 REJECT",
                               "DST-PORT,3478,REJECT" in reject_rules
                               and "DOMAIN-SUFFIX,claude.ai,Ai+" in reject_rules,
                               reject_rules[:100]))
                evaluate("document.querySelector('#proxyfix-cancel').click(); 'ok'")
            evaluate("""
              (() => {
                const sel = document.querySelector('#proxyfix-port');
                sel.value = 'proxy';
                sel.dispatchEvent(new Event('change', { bubbles: true }));
                return 'ok';
              })()
            """)
            wait_for("((document.querySelector('#proxyfix-status')||{}).textContent||'')"
                     ".includes('跟着代理组走')")
        else:
            checks.append(("FlClash 未运行时写入按钮不可用", evaluate(
                "document.querySelector('#proxyfix-apply').disabled") is True))

        # 不带令牌必须 403
        probe2 = evaluate("""
          (async () => {
            const r = await fetch('/api/backups');
            return r.status;
          })()
        """)
        checks.append(("不带令牌被拒", probe2 == 403))

        # 跨站发起的写请求必须发不出去。这里真的换一个来源：导航到 data: 页面，
        # 它的 origin 是 null，再回头打本应用——浏览器会先发预检，
        # 而服务端不响应 OPTIONS，预检过不去，fetch 直接 reject。
        cdp.call("Page.navigate", {"url": "data:text/html,<title>evil</title><body>x"})
        wait_for("document.title === 'evil'")
        probe3 = evaluate("""
          (async () => {
            try {
              const r = await fetch('http://127.0.0.1:%d/api/quit', {
                method: 'POST', mode: 'cors',
                headers: { 'X-CClean-Token': 'x', 'Content-Type': 'application/json' },
                body: '{}'
              });
              return 'passed:' + r.status;
            } catch (e) { return 'blocked'; }
          })()
        """ % APP_PORT)
        checks.append(("跨站写请求被预检挡住", probe3 == "blocked"))

        # 连不带自定义头的「简单请求」也要挡住。no-cors 的 fetch 永远不会 reject，
        # 浏览器拦不住它发出去，所以这里不看返回值——直接看应用有没有被关掉。
        # 真被关掉就说明这条链路是通的，防护形同虚设。
        evaluate("""
          fetch('http://127.0.0.1:%d/api/quit', {
            method: 'POST', mode: 'no-cors',
            headers: { 'Content-Type': 'text/plain' },
            body: '{}'
          }).catch(() => {});
          'sent'
        """ % APP_PORT)
        # 给它 2.5 秒真的把请求发出去。这里不能只探一次：探得早，请求还没到；
        # 探得晚，才看得出它有没有被打垮。所以连续探，任何一次不通就算失败。
        # 探首页而不是 /api/*：后者要令牌，403 会被误判成「应用已死」。
        alive = True
        for _ in range(10):
            time.sleep(0.25)
            try:
                if OPENER.open(f"http://127.0.0.1:{APP_PORT}/", timeout=3).status != 200:
                    alive = False
                    break
            except Exception:
                alive = False
                break
        checks.append(("跨站简单请求打不垮应用", alive))

        goto(url + '?tools=1#privacy:proxyfix-dns-card', READY + " && document.body.classList.contains('tools-only')", "按需维护窗口")
        tools_ui = evaluate("""(() => {
          const messages=[];
          window.webkit={messageHandlers:{host:{postMessage:m=>messages.push(m.action)}}};
          const privacy=document.querySelector('#panel-privacy').classList.contains('active');
          const focused=location.hash==='#privacy:proxyfix-dns-card';
          const noHome=document.querySelector('.primary-tabs [data-tab=home]')===null;
          window.CC.openToolView('settings');
          const settings=!document.querySelector('#panel-settings').classList.contains('active');
          window.CC.openToolView('tower');
          const tower=document.querySelector('#panel-tower').classList.contains('active');
          document.querySelector('#brand').click();
          return {privacy,focused,noHome,settings,tower,messages};
        })()""") or {}
        checks.append(("维护窗口直达修复位置，且守护台页签已撤", tools_ui.get('privacy') and tools_ui.get('focused') and tools_ui.get('noHome')))
        checks.append(("魔塔窗口维护入口转交菜单栏，返回入口接通", tools_ui.get('settings') and tools_ui.get('tower') and tools_ui.get('messages') == ['open-tools','show-monitor']))

        # 菜单栏内工具：先阅读，再按分类选一项；不展示旧窗口与导航。
        (home / '.ccclean' / 'notice.json').unlink(missing_ok=True)
        goto(url + '?tools=1&panel=1#index', "!!window.PanelTools && !!document.querySelector('#pt-ack')", "面板内维护工具")
        wait_for("document.querySelector('#pt-title').textContent==='使用说明与边界'")
        checks.append(("工具首用保留说明且不提前展示修改表单", evaluate("!document.querySelector('#pt-content #privacy-enable') && !document.querySelector('#pt-content #proxyfix-confirm')") is True))
        evaluate("document.querySelector('#pt-ack').click(); 'ok'")
        wait_for("document.querySelector('#pt-title').textContent==='全部工具'")
        embedded = evaluate("""(async()=>{
          const messages=[];window.webkit={messageHandlers:{shield:{postMessage:m=>messages.push(m.action)}}};
          const choices=document.querySelectorAll('#pt-content [data-view]').length;
          const noShell=getComputedStyle(document.querySelector('.topbar')).display==='none' && document.querySelector('.primary-tabs').getClientRects().length===0;
          await PanelTools.show('network');const toolList=document.querySelectorAll('#pt-content [data-view]').length;
          await PanelTools.show('dns');const oneTool=!!document.querySelector('#pt-content #proxyfix-dns-card') && !document.querySelector('#pt-content #ipv6-card');
          const sharedPreview=!!document.querySelector('#pt-content #proxyfix-preview');
          const oldFetch=window.fetch;let sent=[];
          window.fetch=async(u,o)=>{if(String(u)==='/api/proxyfix'&&o?.method==='POST'){sent.push(JSON.parse(o.body));return {ok:true,json:async()=>({ok:true,message:'fixture'})};}return oldFetch(u,o);};
          try {
            proxyfixDns={canApply:true,token:'dns-fixture',familyLabel:'同一家解析器',next:['https://example.invalid/dns-query']};
            document.querySelector('#proxyfix-dns-apply').disabled=false;
            document.querySelector('#proxyfix-dns-apply').click();
            const preview=!document.querySelector('#proxyfix-preview').hidden && sent.length===0;
            document.querySelector('#proxyfix-cancel').click();
            const canceled=document.querySelector('#proxyfix-preview').hidden && sent.length===0;
            await PanelTools.show('index');document.querySelector('#pt-back').click();
            return {choices,noShell,toolList,oneTool,sharedPreview,preview,canceled,messages};
          } finally {window.fetch=oldFetch;}
        })()""") or {}
        checks.append(("工具面板只有五个分类，没有旧窗口外壳", embedded.get('choices')==5 and embedded.get('noShell')))
        checks.append(("分类只展开单个工具，DNS 预览在当前页", embedded.get('toolList')==5 and embedded.get('oneTool') and embedded.get('sharedPreview')))
        checks.append(("原 DNS 预览取消不写入且可以返回哨兵", embedded.get('preview') and embedded.get('canceled') and [x for x in (embedded.get('messages') or []) if x not in ('tool-size','tools-ready')]==['back-panel']))
        for width in (340,420):
            cdp.call('Emulation.setDeviceMetricsOverride', {'width':width,'height':772,'deviceScaleFactor':1,'mobile':False})
            await_result=evaluate("(async()=>{await PanelTools.show('dns');return document.documentElement.scrollWidth<=window.innerWidth;})()")
            checks.append((f"面板内 DNS 工具 {width}px 无横向溢出", await_result is True))
        evaluate("PanelTools.show('index'); 'ok'")
        size=evaluate("Math.ceil(document.querySelector('#panel-tools').getBoundingClientRect().height)")
        shot=cdp.call('Page.captureScreenshot', {'format':'png','clip':{'x':0,'y':0,'width':420,'height':size,'scale':1}}).get('result',{})
        if shot.get('data'): Path('/tmp/shield-tools-embedded.png').write_bytes(base64.b64decode(shot['data']))
        cdp.call('Emulation.setDeviceMetricsOverride', {'width':1440,'height':960,'deviceScaleFactor':1,'mobile':False})

        # 原生哨兵页面用假 bridge 渲染和点击；只记录消息，不启动/终止应用。
        goto((ROOT / 'shield/web/shield.html').as_uri(), "typeof window.SHIELD === 'object'", "加载戒严面板")
        shield_ui = evaluate("""(() => {
          const events=[];
          window.webkit={messageHandlers:{shield:{postMessage:(m)=>events.push(m.action)}}};
          const fixture={enabled:true,level:2,paused:false,claude:false,verdict:'idle',idleState:'ready',sessionActive:false,sessionMessage:'必须检查后使用',sessionStarting:false};
          window.SHIELD.update(fixture);
          const waiting=document.querySelector('#st-title').textContent;
          const visible=!document.querySelector('#session-panel').hidden;
          const placed=document.querySelector('#state').contains(document.querySelector('#btn-start'));
          document.querySelector('#btn-start').click();
          window.SHIELD.update({...fixture,claude:true,sessionActive:true});
          const hidden=document.querySelector('#btn-start').hidden;
          window.confirm=()=>false;
          document.querySelector('#btn-session-end').click();
          const canceled=events.length===1;
          window.confirm=()=>true;
          document.querySelector('#btn-session-end').click();
          return {waiting,visible,placed,hidden,canceled,events};
        })()""") or {}
        checks.append(("戒严待准入不显示就绪", shield_ui.get('waiting') == '需检查后启动' and shield_ui.get('visible') is True))
        checks.append(("启动按钮在状态卡上，不用滚到底部", shield_ui.get('placed') is True))
        checks.append(("戒严检查并启动按钮发送正确动作", (shield_ui.get('events') or [])[:1] == ['session-start']))
        checks.append(("运行中收起启动按钮，结束前需确认", shield_ui.get('hidden') is True and shield_ui.get('canceled') is True and shield_ui.get('events') == ['session-start','session-end']))

        print()
        classified_ui = evaluate("""(() => {
          const events=[];
          window.webkit={messageHandlers:{shield:{postMessage:m=>events.push(m.action)}}};
          const fixture={enabled:true,level:2,paused:false,claude:false,verdict:'idle',idleState:'ready',sessionActive:false,sessionMessage:'请先检查并启动',sessionStarting:false,
            tun:true,tunIface:'utun5',sysProxy:true,sessionChecked:true,sessionMode:'global',connectionsState:'unknown',connectionsDetail:'未发现 Claude 桌面进程，尚无连接样本',
            country:'US',egressMask:'203.0.*.8',egressAt:Date.now()/1000,maskFresh:true,towerData:true,towerState:'ok',
            dnsChecked:true,dnsFake:true,dns:'198.18.0.64',dnsResolverChecked:true,dnsResolverCountry:'CN',dnsResolverOrg:'示例解析器',dnsResolver:'192.0.*.1',dnsEgressSuspect:true,
            stunChecked:true,stun:['203.0.*.8'],transportChecked:true,transportState:'ok',transportLabel:'通 · 1392 ms',domainChecked:true,domainState:'ok',domainLabel:'出口一致',
            tz:'America/New_York',baselineTz:'America/New_York',lastAt:Date.now()/1000,interval:30,hits:[],version:'1.11.1'};
          window.SHIELD.update(fixture);
          const groups=document.querySelectorAll('.fact-group').length;
          const route=getComputedStyle(document.querySelector('#f-route').closest('li'),'::before').content.includes('✓');
          const warn=getComputedStyle(document.querySelector('#f-dns-egress').closest('li'),'::before').content.includes('!');
          const unknown=document.querySelector('#f-connections').closest('li').dataset.st !== 'ok';
          const policy=document.querySelector('#f-policy').textContent==='全局';
          const local=document.querySelector('[data-group=local]');local.open=false;
          window.SHIELD.update({...fixture,tzDrift:true});const reveal=local.open;
          local.open=false;window.SHIELD.update({...fixture,tzDrift:true});const kept=!local.open;
          document.querySelector('[data-tool=dns]').click();
          const strict=document.querySelector('#seg [data-lv="2"]').classList.contains('on');
          window.SHIELD.update({...fixture,level:1});const watch=document.querySelector('#seg [data-lv="1"]').classList.contains('on');
          window.SHIELD.update({...fixture,sessionChecked:false,sessionMode:''});const unconfirmed=document.querySelector('#f-policy').closest('li').dataset.st==='off';
          const toolEvents=events.slice();
          window.SHIELD.update({...fixture,enabled:false,title:'守护中',verdict:'safe'});
          const disabledSafe=document.querySelector('#st-title').textContent==='已停用' && document.querySelector('#state').dataset.v==='idle';
          document.querySelector('#btn-pause').click();const resumed=events[events.length-1]==='resume';
          window.SHIELD.update(fixture);document.body.classList.add('main-window');
          return {groups,route,warn,unknown,policy,reveal,kept,events:toolEvents,strict,watch,unconfirmed,disabledSafe,resumed};
        })()""") or {}
        checks.append(("圆形勾号与警告保留，未确认不算通过", classified_ui.get('groups') == 4 and classified_ui.get('route') and classified_ui.get('warn') and classified_ui.get('unknown')))
        checks.append(("分类异常自动展开且尊重手动折叠", classified_ui.get('reveal') and classified_ui.get('kept')))
        checks.append(("实际代理模式区分已读取与未确认", classified_ui.get('policy') and classified_ui.get('unconfirmed')))
        checks.append(("瞭望戒严选中态与行内工具保留", classified_ui.get('strict') and classified_ui.get('watch') and classified_ui.get('events') == ['repair-dns']))
        checks.append(("停用不显示安全且可以恢复值守", classified_ui.get('disabledSafe') and classified_ui.get('resumed')))
        upstream_ui = evaluate("""(() => {
          window.SHIELD.update({enabled:true,level:2,upstream:true,tun:false,sysProxy:false,tunIface:'en0',
            claude:false,verdict:'idle',idleState:'ready',sessionActive:false,towerState:'ok',
            dnsChecked:true,dnsFake:false,dns:'203.0.113.7',dnsResolverChecked:true,dnsResolverCountry:'US',
            dnsResolver:'203.0.*.1',dnsEgressSuspect:false,stunChecked:true,stun:[],
            transportChecked:true,transportState:'ok',transportLabel:'已测通',domainChecked:true,domainState:'ok',domainLabel:'出口一致',
            tz:'Etc/UTC',baselineTz:'Etc/UTC',hits:[]});
          return {route:document.querySelector('#f-route').closest('li').dataset.st==='off',
            tun:document.querySelector('#f-tun').closest('li').dataset.st==='off',
            policy:document.querySelector('#f-policy').textContent.includes('本机不适用'),
            dns:document.querySelector('#f-dns').textContent.includes('真实地址'),
            resolver:document.querySelector('#f-dns-egress').closest('li').dataset.st==='ok'};
        })()""") or {}
        checks.append(("上游代理无本机 TUN 时仍展示探测结果，本机路由不误报", all(upstream_ui.get(k) for k in ('route','tun','policy','dns','resolver'))))
        managed_vm_ui = evaluate("""(() => {
          window.SHIELD.update({enabled:true,level:2,vmManaged:true,vmProtected:true,vmUDPBlocked:true,
            upstream:false,tun:true,sysProxy:false,tunIface:'utun0',sessionChecked:true,sessionMode:'rule',
            claude:false,verdict:'idle',idleState:'ready',towerState:'ok',
            dnsChecked:true,dnsFake:true,dns:'198.19.0.47',dnsResolverChecked:true,dnsResolverCountry:'US',
            dnsResolver:'203.0.*.1',dnsEgressSuspect:false,stunChecked:false,stun:[],
            transportChecked:true,transportState:'ok',domainChecked:true,domainState:'ok',
            tz:'Etc/UTC',baselineTz:'Etc/UTC',hits:[]});
          return !document.querySelector('#vm-network-row').hidden &&
            document.querySelector('#f-vm-network').closest('li').dataset.st==='ok' &&
            document.querySelector('#f-policy').textContent.includes('规则全代理') &&
            document.querySelector('#f-udp').closest('li').dataset.st==='ok' &&
            document.querySelector('#btn-upstream').hidden;
        })()""")
        checks.append(("虚拟机规则模式、断网保护及 UDP 拒绝结果准确显示", managed_vm_ui is True))

        cdp.call('Emulation.setDeviceMetricsOverride', {'width':420,'height':1000,'deviceScaleFactor':1,'mobile':False})
        shot=cdp.call('Page.captureScreenshot', {'format':'png','captureBeyondViewport':True}).get('result',{})
        if shot.get('data'): Path('/tmp/shield-classified-actual.png').write_bytes(base64.b64decode(shot['data']))
        for width in (340,420):
            cdp.call('Emulation.setDeviceMetricsOverride', {'width':width,'height':1000,'deviceScaleFactor':1,'mobile':False})
            checks.append((f"分类面板 {width}px 无横向溢出", evaluate('document.documentElement.scrollWidth <= window.innerWidth') is True))

        ok = True
        for item in checks:
            name, cond = item[0], item[1]
            detail = item[2] if len(item) > 2 else ""
            print(f"  {'✓' if cond else '✗'} {name}" + ("" if cond or not detail else f"  —— {detail}"))
            ok = ok and bool(cond)

        if js_errors:
            ok = False
            print("\n  JS 报错：")
            for e in js_errors[:10]:
                print(f"    {e}")
        if failed:
            ok = False
            print("\n  失败请求：")
            for f in failed[:10]:
                print(f"    {f}")

        print(f"\n{'='*46}\n  {'全部通过' if ok else '有失败项'}\n{'='*46}")
        return 0 if ok else 1
    finally:
        if cdp:
            cdp.close()
        chrome.terminate()
        app.terminate()
        for p in (chrome, app):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
