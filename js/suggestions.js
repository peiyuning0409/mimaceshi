// suggestions.js —— 基于 NIST SP 800-63B Rev.4 与 OWASP 2025 的改进建议
// 纯本地计算：不联网、不记录、不上传。

// 生成改进建议列表
function buildSuggestions(pwd, analysis, score) {
  const tips = [];
  const a = analysis;
  const len = a.len;

  // 1. 黑名单命中
  if (score === 0 && typeof COMMON_PASSWORDS !== 'undefined' && COMMON_PASSWORDS.has(pwd)) {
    tips.push({ level: 'danger', text: '该密码出现在常见/已泄露密码黑名单中，攻击者会优先尝试，必须立即更换。' });
  }

  // 2. 长度建议（NIST SP 800-63B Rev.4：单因素最低 15 字符，MFA 下最低 8 字符）
  if (len < 8) {
    tips.push({ level: 'danger', text: '长度不足 8 位，即使启用 MFA 也不满足 NIST SP 800-63B Rev.4 的最低要求。' });
  } else if (len < 15) {
    tips.push({ level: 'warning', text: '长度不足 15 位。NIST SP 800-63B Rev.4 建议单因素密码至少 15 字符；若未启用 MFA，请加长。' });
  } else {
    tips.push({ level: 'good', text: '长度达到 15 位以上，满足 NIST SP 800-63B Rev.4 对单因素密码的建议。' });
  }

  // 3. 字符集多样性
  const used = Object.keys(a.has).filter(k => a.has[k]).length;
  if (used < 3) {
    tips.push({ level: 'warning', text: '字符类型单一（仅 ' + used + ' 类）。混合大小写、数字与符号可显著提升熵值。' });
  } else {
    tips.push({ level: 'good', text: '已使用 ' + used + ' 类字符，多样性良好。' });
  }

  // 4. 熵值评估
  if (a.entropy < 60) {
    tips.push({ level: 'warning', text: '熵值仅约 ' + a.entropy.toFixed(1) + ' bit，低于 60 bit 的安全线，建议提升到 80 bit 以上。' });
  } else if (a.entropy < 80) {
    tips.push({ level: 'good', text: '熵值约 ' + a.entropy.toFixed(1) + ' bit，达到中等安全水平，可继续提升。' });
  } else {
    tips.push({ level: 'good', text: '熵值约 ' + a.entropy.toFixed(1) + ' bit，达到强密码水平。' });
  }

  // 5. 常见模式检测
  const lower = pwd.toLowerCase();
  if (/^(.)\1+$/.test(pwd)) {
    tips.push({ level: 'danger', text: '密码为重复字符（如 111111），极易被破解。' });
  }
  if (/^(1234|12345|123456|qwerty|asdf|zxcv|password|admin|iloveyou|woaini)/.test(lower)) {
    tips.push({ level: 'danger', text: '密码以常见弱密码开头，属于高危模式。' });
  }
  if (/^(19|20)\d{2}$/.test(pwd) || /(19|20)\d{2}$/.test(pwd)) {
    tips.push({ level: 'warning', text: '包含年份数字（如生日/纪念年），易被针对性猜测。' });
  }
  if (/^\d+$/.test(pwd)) {
    tips.push({ level: 'warning', text: '纯数字密码，即使较长也容易被掩码攻击（mask attack）快速破解。' });
  }

  // 6. 键盘序列
  const kb = ['qwerty', 'asdfgh', 'zxcvbn', '1qaz', '2wsx', '3edc', 'qazwsx', '1q2w3e4r'];
  for (const seq of kb) {
    if (lower.includes(seq)) {
      tips.push({ level: 'warning', text: '包含键盘连续序列（' + seq + '），属于常见弱模式。' });
      break;
    }
  }

  // 7. 通用建议（OWASP 2025）
  tips.push({ level: 'info', text: 'OWASP 2025 建议：优先使用密码管理器生成并保存随机长密码，避免在多个站点复用同一密码。' });
  tips.push({ level: 'info', text: 'NIST SP 800-63B Rev.4 建议：不要设置强制定期更换密码的规则，除非出现泄露迹象；应重点筛查密码是否出现在已知泄露列表中。' });
  tips.push({ level: 'info', text: '务必为账户启用多因素认证（MFA），即使密码泄露也能提供第二道防线。' });

  return tips;
}

window.buildSuggestions = buildSuggestions;
