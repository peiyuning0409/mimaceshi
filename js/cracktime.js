// cracktime.js —— 基于 RTX 4090 hashcat 实测基准的破解时间估算
// 数据来源：hashcat 7.0.0 在 RTX 4090 单卡实测（2025-08），RTX 5090 约快 36%-47%
// 纯本地计算：不联网、不记录、不上传。

// 各算法在 RTX 4090 单卡上的每秒尝试次数（hashcat 7.0.0 实测）
const BENCH_4090 = {
  'MD5':        163.4e9,   // 163.4 GH/s
  'NTLM':       271.9e9,   // 271.9 GH/s
  'SHA-1':      58.6e9,    // 58.6 GH/s
  'SHA-256':    22.1e9,    // 22.1 GH/s
  'SHA-512':    7.5e9,     // 7.5 GH/s
  'WPA2 (PBKDF2)': 2.66e6, // 2.66 MH/s
  'bcrypt (cost 12)': 3200,// 3200 H/s
  'Argon2id':   1900       // 1900 H/s
};

// 离线攻击场景：单卡 / 高端集群 / 国家级（相对单卡 RTX 4090 的倍数）
const OFFLINE_TIERS = [
  { name: '单卡 RTX 4090', mult: 1 },
  { name: '高端 GPU 集群', mult: 1000 },
  { name: '国家级（超算级）', mult: 100000 }
];

// 在线攻击场景：受网站速率限制
const ONLINE_TIERS = [
  { name: '慢速在线攻击（限速 10 次/秒）', rate: 10 },
  { name: '快速在线攻击（分布式 1000 次/秒）', rate: 1000 }
];

// 人类可读时间格式化
function formatDuration(seconds) {
  if (seconds < 1) return '不足 1 秒';
  const units = [
    [31557600, '年'], [2629800, '月'], [604800, '周'], [86400, '天'],
    [3600, '小时'], [60, '分钟'], [1, '秒']
  ];
  for (const [sec, name] of units) {
    if (seconds >= sec) {
      const v = seconds / sec;
      if (v >= 100) return v.toExponential(2) + ' ' + name;
      return (v >= 10 ? v.toFixed(0) : v.toFixed(1)) + ' ' + name;
    }
  }
  return seconds.toFixed(1) + ' 秒';
}

// 破解概率评估文案
function evaluateRisk(seconds) {
  if (seconds < 1) return '立即被破解';
  if (seconds < 60) return '1 分钟内可破';
  if (seconds < 3600) return '1 小时内可破';
  if (seconds < 86400) return '1 天内可破';
  if (seconds < 31557600) return '1 年内可破';
  if (seconds < 31557600 * 100) return '数十年内可破';
  if (seconds < 31557600 * 10000) return '上千年内可破';
  return '远超人类文明尺度';
}

// 计算破解时间：组合数 ÷ 每秒尝试次数 ÷ 2（平均尝试一半空间）
function computeCrackSeconds(analysis, rate) {
  const combos = Math.pow(analysis.pool, analysis.len);
  return combos / rate / 2;
}

// 构建离线攻击表格行
function buildOfflineRows(analysis) {
  const rows = [];
  for (const [algo, rate] of Object.entries(BENCH_4090)) {
    const base = computeCrackSeconds(analysis, rate);
    const cells = OFFLINE_TIERS.map(t => {
      const sec = base / t.mult;
      return { time: formatDuration(sec), risk: evaluateRisk(sec) };
    });
    rows.push({ name: algo, rate: formatRate(rate), cells });
  }
  return rows;
}

// 构建在线攻击表格行
function buildOnlineRows(analysis) {
  const rows = [];
  for (const t of ONLINE_TIERS) {
    const sec = computeCrackSeconds(analysis, t.rate);
    rows.push({
      name: t.name,
      rate: formatRate(t.rate),
      cells: [{ time: formatDuration(sec), risk: evaluateRisk(sec) }]
    });
  }
  return rows;
}

// 速率格式化
function formatRate(rate) {
  if (rate >= 1e9) return (rate / 1e9).toFixed(1) + ' 亿次/秒';
  if (rate >= 1e6) return (rate / 1e6).toFixed(1) + ' 百万次/秒';
  if (rate >= 1e3) return (rate / 1e3).toFixed(1) + ' 千次/秒';
  return rate + ' 次/秒';
}

window.computeCrackSeconds = computeCrackSeconds;
window.buildOfflineRows = buildOfflineRows;
window.buildOnlineRows = buildOnlineRows;
window.formatDuration = formatDuration;
window.formatRate = formatRate;
window.evaluateRisk = evaluateRisk;
window.BENCH_4090 = BENCH_4090;
window.OFFLINE_TIERS = OFFLINE_TIERS;
window.ONLINE_TIERS = ONLINE_TIERS;
