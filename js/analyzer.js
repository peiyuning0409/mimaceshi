// analyzer.js —— 密码字符集识别、熵值计算与强度评分
// 纯本地计算：不联网、不记录、不上传。

// 字符集定义（用于熵值计算）
const CHARSETS = {
  lower: 26,      // 小写字母 a-z
  upper: 26,      // 大写字母 A-Z
  digit: 10,      // 数字 0-9
  symbol: 33,     // 常见符号 !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
  other: 94       // 其他可打印 ASCII / Unicode 字符（按 94 估算）
};

// 分析密码：返回字符集构成、实际字符集大小、熵值
function analyzePassword(pwd) {
  if (!pwd) return null;
  const has = { lower: false, upper: false, digit: false, symbol: false, other: false };
  for (const ch of pwd) {
    const code = ch.codePointAt(0);
    if (ch >= 'a' && ch <= 'z') has.lower = true;
    else if (ch >= 'A' && ch <= 'Z') has.upper = true;
    else if (ch >= '0' && ch <= '9') has.digit = true;
    else if (code >= 0x21 && code <= 0x7E) has.symbol = true; // 可打印 ASCII 符号
    else has.other = true; // 空格、中文、其他 Unicode
  }

  // 实际字符集大小 = 各已用字符集之和
  let pool = 0;
  for (const k in CHARSETS) if (has[k]) pool += CHARSETS[k];

  const len = Array.from(pwd).length; // 按 Unicode 码点计数
  // 熵值（比特）= 长度 × log2(字符集大小)
  const entropy = len * Math.log2(Math.max(pool, 1));

  return { len, pool, has, entropy };
}

// 强度评分 0-5（基于熵值与密码学强度思路）
// 0=极弱 1=很弱 2=弱 3=中等 4=强 5=极强
function scorePassword(pwd, analysis) {
  if (!pwd) return 0;
  const a = analysis || analyzePassword(pwd);
  const e = a.entropy;
  const len = a.len;

  // 黑名单命中直接判 0
  if (typeof COMMON_PASSWORDS !== 'undefined' && COMMON_PASSWORDS.has(pwd)) return 0;

  if (len === 0) return 0;
  if (e < 28) return 1;          // <28 bit
  if (e < 36) return 2;          // 28-35 bit
  if (e < 60) return 3;          // 36-59 bit
  if (e < 80) return 4;          // 60-79 bit
  return 5;                      // >=80 bit
}

// 强度等级文案与颜色（对应 css 中 strength-0~5）
const STRENGTH_META = [
  { label: '极弱', color: '#e74c3c' },
  { label: '很弱', color: '#e67e22' },
  { label: '弱',   color: '#f1c40f' },
  { label: '中等', color: '#2ecc71' },
  { label: '强',   color: '#27ae60' },
  { label: '极强', color: '#00b894' }
];

// 暴露到全局
window.analyzePassword = analyzePassword;
window.scorePassword = scorePassword;
window.STRENGTH_META = STRENGTH_META;
