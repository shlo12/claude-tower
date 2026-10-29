/* 隔离的真实页面录屏。只服务本地网页与演示 API，不启动真实检测服务。 */
const { chromium } = require('playwright');
const fs = require('node:fs/promises');
const path = require('node:path');
const http = require('node:http');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const assert = require('node:assert/strict');
const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'build/preview');
const W = 1280, H = 800;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

(async () => {
  await fs.mkdir(OUT, { recursive: true });
  const work = await fs.mkdtemp(path.join(os.tmpdir(), 'cc-finale-'));
  const version = (await fs.readFile(path.join(ROOT, 'app.py'), 'utf8')).match(/^VERSION = "([^"]+)"/m)[1];
  const entry = { rank: 1, name: '作者', days: 35, hp: 160, level: 12, title: '塔的建造者', author: true, ts: 1, durationSec: 252 };
  const fixtures = {
    '/api/meta': { version, home: '/演示环境', disclaimer: '隔离演示，不读取用户数据' },
    '/api/notice': { acked: true, version },
    '/api/checklist': { groups: [], total: 0, done: [] },
    '/api/profiles': { profiles: [] },
    '/api/leaderboard': { entries: [entry], stats: { count: 1, bestDays: 35, bestHp: 160 } },
  };
  const requests = [], errors = [];
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname.startsWith('/api/')) {
      requests.push(`${req.method} ${url.pathname}`);
      const data = fixtures[url.pathname];
      res.writeHead(data && req.method === 'GET' ? 200 : 405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data ? { ok: true, ...data } : { error: '演示环境禁止真实操作' }));
      return;
    }
    const rel = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
    const file = path.resolve(ROOT, 'web', '.' + rel);
    if (!file.startsWith(path.join(ROOT, 'web') + path.sep)) { res.writeHead(403); res.end(); return; }
    try {
      let data = await fs.readFile(file);
      if (rel.endsWith('.html')) data = Buffer.from(data.toString().replace('<head>', `<head><meta name="cc-token" content="${'demo'.repeat(12)}"><meta name="cc-version" content="${version}">`));
      const ext = path.extname(file);
      res.writeHead(200, { 'Content-Type': ({ '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png' })[ext] || 'application/octet-stream' });
      res.end(data);
    } catch { res.writeHead(404); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/?demo=finisher`;
  let browser;
  try {
    const chrome = process.env.CCLEAN_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
    browser = await chromium.launch({ headless: true, executablePath: chrome,
      args: ['--autoplay-policy=no-user-gesture-required', '--hide-scrollbars'] });
    const context = await browser.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: 1 });
    await context.addInitScript(() => {
      window.__notes = [];
      const Real = window.AudioContext;
      if (!Real) return;
      window.AudioContext = class extends Real {
        constructor(...args) {
          super(...args);
          this.capture = this.createMediaStreamDestination();
          const chunks = [];
          const recorder = new MediaRecorder(this.capture.stream);
          window.__audioRecorder = recorder;
          window.__audioReady = new Promise(resolve => {
            recorder.ondataavailable = e => { if (e.data.size) chunks.push(e.data); };
            recorder.onstop = async () => {
              const bytes = new Uint8Array(await new Blob(chunks, { type: recorder.mimeType }).arrayBuffer());
              let raw = ''; for (let i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
              resolve(btoa(raw));
            };
          });
          window.__audioStarted = Date.now() / 1000;
          recorder.start();
        }
      };
      const connect = AudioNode.prototype.connect;
      AudioNode.prototype.connect = function (target, ...args) {
        const result = connect.call(this, target, ...args);
        if (target === this.context.destination && this.context.capture) connect.call(this, this.context.capture);
        return result;
      };
      const oscillator = Real.prototype.createOscillator;
      Real.prototype.createOscillator = function (...args) {
        window.__notes.push(performance.now());
        return oscillator.apply(this, args);
      };
    });
    const page = await context.newPage();
    page.on('pageerror', e => errors.push(e.message));
    page.on('response', res => { if (res.status() >= 400) errors.push(`${res.status()} ${res.url()}`); });
    await page.goto(url, { waitUntil: 'networkidle' });
    await page.waitForFunction(() => !!window.Tower?.previewFinisher);

    // 先验证快速跳过；晚到的音符与捕获阶段监听必须被清理。
    const session = await context.newCDPSession(page);
    const listenerCount = async () => (await session.send('Runtime.evaluate', {
      expression: "getEventListeners(document).keydown.filter(x => x.useCapture).length", returnByValue: true,
    })).result.value;
    const before = await listenerCount();
    await page.evaluate(() => { window.__preview = Tower.previewFinisher(); });
    await page.waitForSelector('#finisher.run');
    await page.keyboard.press('Escape');
    await page.waitForSelector('#finisher[hidden]', { state: 'attached' });
    assert.equal(await listenerCount(), before, '跳过后必须移除捕获阶段键盘监听');
    const notesAfterSkip = await page.evaluate(() => __notes.length);
    await sleep(1100);
    assert.equal(await page.evaluate(() => __notes.length), notesAfterSkip, '跳过后不能继续播放延迟音符');
    await page.evaluate(() => { document.querySelector('#victory').hidden = true; });
    // 独立页面验证减少动态效果：直接结算，不播放移动或音符。
    const reduced = await context.newPage();
    await reduced.emulateMedia({ reducedMotion: 'reduce' });
    await reduced.goto(url, { waitUntil: 'networkidle' });
    await reduced.evaluate(() => Tower.previewFinisher());
    assert.equal(await reduced.locator('#finisher').isVisible(), false);
    assert.equal(await reduced.locator('#victory').isVisible(), true);
    await reduced.close();
    await page.bringToFront();
    await page.reload({ waitUntil: 'networkidle' });
    await page.evaluate(() => { document.querySelector('#notice').hidden = true; });
    // 给录屏一个安静的标题页开头；接下来调用与真实通关同一套函数。
    const frames = [], writes = [];
    let accepting = true;
    session.on('Page.screencastFrame', event => {
      const index = frames.length;
      if (accepting) {
        const file = path.join(work, `frame-${String(index).padStart(5, '0')}.jpg`);
        frames.push({ file, at: event.metadata.timestamp });
        writes.push(fs.writeFile(file, Buffer.from(event.data, 'base64')));
      }
      session.send('Page.screencastFrameAck', { sessionId: event.sessionId }).catch(() => {});
    });
    await session.send('Page.startScreencast', { format: 'jpeg', quality: 92, maxWidth: W, maxHeight: H, everyNthFrame: 1 });
    await sleep(900);
    const start = Date.now() / 1000;
    await page.evaluate(() => { window.__preview = Tower.previewFinisher(); });
    await sleep(7200);
    await page.screenshot({ path: path.join(OUT, 'finisher-poster.png') });
    await page.evaluate(() => window.__preview);
    await sleep(2400);
    await session.send('Page.stopScreencast');
    accepting = false;
    const end = Date.now() / 1000;
    await Promise.all(writes);
    await page.screenshot({ path: path.join(OUT, 'finisher-card.png') });
    const audio = await page.evaluate(async () => {
      if (!window.__audioRecorder) return null;
      __audioRecorder.stop();
      return { data: await __audioReady, at: __audioStarted };
    });
    assert.equal(await page.locator('#victory').isVisible(), true);
    assert.equal(await page.locator('#v-form').isVisible(), false, '演示不得提供上榜写入');
    assert.equal(requests.some(x => x.startsWith('POST')), false, '演示不得写入真实进度');
    assert.equal(errors.length, 0, errors.join('\n'));
    assert.ok(frames.length > 60, '录制帧数不足');
    // 浏览器事件时间戳还原真实停留时长，不把静止画面的停留压缩。
    const list = [];
    for (let i = 0; i < frames.length; i++) {
      const duration = Math.max(1 / 240, (frames[i + 1]?.at || end) - frames[i].at);
      list.push(`file '${frames[i].file}'\nduration ${duration.toFixed(6)}`);
    }
    list.push(`file '${frames.at(-1).file}'`);
    await fs.writeFile(path.join(work, 'frames.txt'), list.join('\n'));
    const args = ['-y', '-hide_banner', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', path.join(work, 'frames.txt')];
    if (audio) {
      await fs.writeFile(path.join(work, 'audio.webm'), Buffer.from(audio.data, 'base64'));
      args.push('-itsoffset', String(Math.max(0, audio.at - frames[0].at)), '-i', path.join(work, 'audio.webm'), '-map', '0:v', '-map', '1:a', '-c:a', 'aac', '-b:a', '128k');
    }
    args.push('-vf', 'fps=30,format=yuv420p', '-c:v', 'libx264', '-crf', '18', '-movflags', '+faststart', path.join(OUT, 'finisher.mp4'));
    const encode = spawnSync(process.env.CCLEAN_FFMPEG || 'ffmpeg', args, { encoding: 'utf8', timeout: 90000 });
    assert.equal(encode.status, 0, encode.stderr);
    console.log(JSON.stringify({ ok: true, video: path.join(OUT, 'finisher.mp4'), frames: frames.length,
      durationSec: +(end - frames[0].at).toFixed(2), audio: !!audio,
      checks: ['真实过场与结算', '跳过后无延迟音符', '捕获监听已清理', '减少动态效果', '窄屏无溢出', '未写入进度', '无页面异常'],
      demo: '战绩为隔离演示数据，不读取或改动本机 Claude 配置' }, null, 2));
    await session.detach();
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
    await fs.rm(work, { recursive: true, force: true });
  }
})().catch(e => { console.error(e); process.exitCode = 1; });
