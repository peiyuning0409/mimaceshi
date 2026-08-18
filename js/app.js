// app.js —— 事件绑定、UI 更新、密码生成器、零存储逻辑
// 纯本地计算：不联网、不记录、不上传。所有计算均在浏览器本地完成。

(function () {
  'use strict';

  // DOM 元素
  const passwordInput = document.getElementById('passwordInput');
  const toggleBtn = document.getElementById('toggleBtn');
  const clearBtn = document.getElementById('clearBtn');
  const charCount = document.getElementById('charCount');
  const charSetInfo = document.getElementById('charSetInfo');
  const meterFill = document.getElementById('meterFill');
  const scoreNum = document.getElementById('scoreNum');
  const scoreLabel = document.getElementById('scoreLabel');
  const entropyNum = document.getElementById('entropyNum');
  const crackSection = document.getElementById('crackSection');
  const crackTableBody = document.getElementById('crackTableBody');
  const crackNote = document.getElementById('crackNote');
  const analysisSection = document.getElementById('analysisSection');
  const analysisList = document.getElementById('analysisList');
  const suggestSection = document.getElementById('suggestSection');
  const suggestList = document.getElementById('suggestList');
  const tabBtns = document.querySelectorAll('.tab-btn');
  const genUpper = document.getElementById('genUpper');
  const genLower = document.getElementById('genLower');
  const genDigit = document.getElementById('genDigit');
  const genSymbol = document.getElementById('genSymbol');
  const genLength = document.getElementById('genLength');
  const genBtn = document.getElementById('genBtn');
  const genResult = document.getElementById('genResult');
  const genPassword = document.getElementById('genPassword');
  const copyGenBtn = document.getElementById('copyGenBtn');

  let currentAttack = 'offline'; // 当前攻击模式

  // 更新分析结果
  function update() {
    const pwd = passwordInput.value;
    if (!pwd) {
      meterFill.style.width = '0%';
      meterFill.className = 'meter-fill';
      scoreNum.textContent = '—';
      scoreLabel.textContent = '等待输入';
      entropyNum.textContent = '0';
      charCount.textContent = '0 个字符';
      charSetInfo.textContent = '—';
      crackSection.style.display = 'none';
      analysisSection.style.display = 'none';
      suggestSection.style.display = 'none';
      return;
    }

    const analysis = analyzePassword(pwd);
    const score = scorePassword(pwd, analysis);

    // 强度条
    const pct = Math.min(100, Math.round((score + 1) / 6 * 100));
    meterFill.style.width = pct + '%';
    meterFill.className = 'meter-fill strength-' + score;
    scoreNum.textContent = score;
    scoreLabel.textContent = STRENGTH_META[score].label;
    scoreLabel.style.color = STRENGTH_META[score].color;

    // 基础指标
    entropyNum.textContent = analysis.entropy.toFixed(1);
    charCount.textContent = analysis.len + ' 个字符';
    const parts = [];
    if (analysis.has.lower) parts.push('小写');
    if (analysis.has.upper) parts.push('大写');
    if (analysis.has.digit) parts.push('数字');
    if (analysis.has.symbol) parts.push('符号');
    if (analysis.has.other) parts.push('其他/中文');
    charSetInfo.textContent = parts.length ? parts.join('、') : '—';

    // 破解时间表
    renderCrackTable(analysis);
    crackSection.style.display = 'block';

    // 详细分析
    renderAnalysis(analysis, score, pwd);
    analysisSection.style.display = 'block';

    // 建议
    const tips = buildSuggestions(pwd, analysis, score);
    suggestList.innerHTML = tips.map(t =>
      '<div class="suggest-item suggest-' + t.level + '">' + t.text + '</div>'
    ).join('');
    suggestSection.style.display = 'block';
  }

  // 渲染破解时间表
  function renderCrackTable(analysis) {
    let rows, note;
    if (currentAttack === 'offline') {
      rows = buildOfflineRows(analysis);
      note = '离线攻击指攻击者已获得密码哈希（如数据库泄露），可在本地用 GPU 高速尝试。';
    } else {
      rows = buildOnlineRows(analysis);
      note = '在线攻击指攻击者直接对网站登录接口尝试，受速率限制影响，速度远低于离线攻击。';
    }

    let html = '';
    for (const row of rows) {
      for (let i = 0; i < row.cells.length; i++) {
        const tierName = currentAttack === 'offline'
          ? OFFLINE_TIERS[i].name
          : ONLINE_TIERS[i].name;
        const cell = row.cells[i];
        html += '<tr>';
        html += '<td>' + row.name + '<br><span class="tier-name">' + tierName + '</span></td>';
        html += '<td>' + row.rate + '</td>';
        html += '<td>' + cell.time + '</td>';
        html += '<td>' + cell.risk + '</td>';
        html += '</tr>';
      }
    }
    crackTableBody.innerHTML = html;
    crackNote.textContent = note;
  }

  // 渲染详细分析
  function renderAnalysis(analysis, score, pwd) {
    const items = [];
    items.push({ k: '密码长度', v: analysis.len + ' 个字符' });
    items.push({ k: '字符集大小', v: analysis.pool + ' 种字符' });
    items.push({ k: '估算熵值', v: analysis.entropy.toFixed(1) + ' bits' });
    items.push({ k: '强度评分', v: score + ' / 5（' + STRENGTH_META[score].label + '）' });
    const inBlacklist = typeof COMMON_PASSWORDS !== 'undefined' && COMMON_PASSWORDS.has(pwd);
    items.push({ k: '黑名单筛查', v: inBlacklist ? '命中（常见/已泄露密码）' : '未命中' });
    items.push({ k: '是否纯数字', v: /^\d+$/.test(pwd) ? '是' : '否' });
    items.push({ k: '是否重复字符', v: /^(.)\1+$/.test(pwd) ? '是' : '否' });

    analysisList.innerHTML = items.map(it =>
      '<div class="analysis-item"><span class="a-key">' + it.k + '</span><span class="a-val">' + it.v + '</span></div>'
    ).join('');
  }

  // 密码生成器
  function generate() {
    const len = parseInt(genLength.value, 10) || 20;
    const useUpper = genUpper.checked;
    const useLower = genLower.checked;
    const useDigit = genDigit.checked;
    const useSymbol = genSymbol.checked;

    let pool = '';
    if (useLower) pool += 'abcdefghijkmnopqrstuvwxyz';
    if (useUpper) pool += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    if (useDigit) pool += '23456789';
    if (useSymbol) pool += '!@#$%^&*()-_=+[]{};:,.<>?';
    if (!pool) { genPassword.textContent = '请至少选择一种字符类型'; genResult.style.display = 'block'; return; }

    // 使用 crypto.getRandomValues 保证加密安全随机
    const arr = new Uint32Array(len);
    crypto.getRandomValues(arr);
    let pwd = '';
    for (let i = 0; i < len; i++) pwd += pool[arr[i] % pool.length];
    genPassword.textContent = pwd;
    genResult.style.display = 'block';
  }

  // 复制生成结果
  function copyResult() {
    const text = genPassword.textContent;
    if (!text || text === '请至少选择一种字符类型') return;
    navigator.clipboard.writeText(text).then(() => {
      copyGenBtn.textContent = '已复制';
      setTimeout(() => { copyGenBtn.textContent = '复制'; }, 1500);
    });
  }

  // 显示/隐藏密码
  function toggleVisible() {
    const isHidden = passwordInput.type === 'password';
    passwordInput.type = isHidden ? 'text' : 'password';
    toggleBtn.textContent = isHidden ? '🙈' : '👁';
  }

  // 清空输入
  function clearInput() {
    passwordInput.value = '';
    update();
    passwordInput.focus();
  }

  // 攻击模式切换
  function switchAttack(mode) {
    currentAttack = mode;
    tabBtns.forEach(b => b.classList.toggle('active', b.dataset.attack === mode));
    if (passwordInput.value) {
      const analysis = analyzePassword(passwordInput.value);
      renderCrackTable(analysis);
    }
  }

  // 事件绑定
  passwordInput.addEventListener('input', update);
  toggleBtn.addEventListener('click', toggleVisible);
  clearBtn.addEventListener('click', clearInput);
  genBtn.addEventListener('click', generate);
  copyGenBtn.addEventListener('click', copyResult);
  tabBtns.forEach(b => b.addEventListener('click', () => switchAttack(b.dataset.attack)));

  // 初始渲染
  update();
})();
