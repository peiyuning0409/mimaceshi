// suggestions.js —— 密码改进建议生成
// 纯本地计算：不联网、不记录、不上传。

// 生成改进建议列表：每条包含 问题原因 + 改进动作 + 预期效果
function buildSuggestions(pwd, analysis, score) {
  const tips = [];
  const a = analysis;
  const len = a.len;
  const lower = pwd.toLowerCase();

  // 1. 黑名单命中 —— 最高危
  if (typeof COMMON_PASSWORDS !== 'undefined' && COMMON_PASSWORDS.has(pwd)) {
    tips.push({
      level: 'danger',
      text: '该密码出现在已泄露密码库中（这类密码多来自历次真实数据泄露事件，攻击者会优先用它们尝试撞库登录）。必须立即更换，且千万不要在其他任何网站/应用上继续使用。'
    });
  }

  // 2. 长度
  if (len < 8) {
    tips.push({
      level: 'danger',
      text: '长度只有 ' + len + ' 位，短于 8 位。现代攻击工具每秒可穷举上亿个组合，这么短的密码即使在普通电脑上也能在几分钟内被暴力破解。建议至少加长到 15 位以上，可以用一句你能记住的话的首字母组合。'
    });
  } else if (len < 12) {
    tips.push({
      level: 'warning',
      text: '长度 ' + len + ' 位偏短。每增加 1 位字符，破解所需的尝试次数就翻几倍——从 8 位加到 12 位，暴力破解耗时大约会从"分钟级"提升到"年级"。建议加长到 15 位以上，例如用 3~4 个随机单词拼接。'
    });
  } else if (len < 15) {
    tips.push({
      level: 'warning',
      text: '长度 ' + len + ' 位属于"能用但不稳"的区间。若目标站点被拖库，GPU 集群可以在几天内跑完 12~14 位纯小写或纯数字的密码。建议提升到 15 位以上，这是公认的舒适安全线。'
    });
  } else {
    tips.push({
      level: 'good',
      text: '长度 ' + len + ' 位，已达到推荐的安全线以上。长度是密码强度最核心的变量，继续保持。'
    });
  }

  // 3. 字符集多样性
  const used = Object.keys(a.has).filter(k => a.has[k]).length;
  if (used < 2) {
    tips.push({
      level: 'warning',
      text: '只用了 1 类字符。字符类型越单一，可用的组合空间越小，攻击者用专门的字典（纯数字库/纯字母库）就能快速命中。建议混合大小写字母、数字和符号，例如把 loveyou 改成 L0v3-You_2026!。'
    });
  } else if (used < 3) {
    tips.push({
      level: 'warning',
      text: '仅 ' + used + ' 类字符（常见的是字母+数字）。少了符号这一档，排列组合空间约缩小几十到几百倍。加入符号或大小写混合（如把 mima123 改成 Mi@ma#2026!），破解耗时能提升几个数量级。'
    });
  } else if (used < 4) {
    tips.push({
      level: 'good',
      text: '已使用 ' + used + ' 类字符，基础不错。若密码是纯小写字母+数字，建议把其中几个字母改成大写或换成符号，还能再上一个台阶。'
    });
  } else {
    tips.push({
      level: 'good',
      text: '大小写、数字、符号都齐了（' + used + ' 类字符），组合空间已最大化利用。'
    });
  }

  // 4. 熵值评估
  if (a.entropy < 40) {
    tips.push({
      level: 'danger',
      text: '熵值仅约 ' + a.entropy.toFixed(1) + ' bit。这意味着该密码的"不确定度"极低，攻击者用常见的密码字典/规则枚举，几乎可以秒破。建议彻底重设，参考"随机单词串+数字符号"的构造方式。'
    });
  } else if (a.entropy < 60) {
    tips.push({
      level: 'warning',
      text: '熵值约 ' + a.entropy.toFixed(1) + ' bit，处于容易被定向攻击（如生日、常用词字典攻击）覆盖的范围。把长度加长 4~6 位，或混入大小写和符号，熵值可轻松翻倍。'
    });
  } else if (a.entropy < 80) {
    tips.push({
      level: 'good',
      text: '熵值约 ' + a.entropy.toFixed(1) + ' bit，达到中等安全水平。对绝大多数场景已足够，若想更稳妥可再加一段随机字符。'
    });
  } else {
    tips.push({
      level: 'good',
      text: '熵值约 ' + a.entropy.toFixed(1) + ' bit，已达到强密码级别，即使离线拖库也要数百年才能跑完。'
    });
  }

  // 5. 常见模式检测
  if (/^(.)\1+$/.test(pwd)) {
    tips.push({
      level: 'danger',
      text: '整串密码都是同一个字符（如 aaaaaa / 111111）。这种模式在所有泄露数据里出现频率最高，任何字典攻击的第一步就会尝试它，基本等于没设密码。'
    });
  }
  if (/^(1234|12345|123456|1234567|12345678|123456789|1234567890|qwerty|asdf|zxcv|password|admin|iloveyou|woaini)/.test(lower)) {
    tips.push({
      level: 'danger',
      text: '密码以排名最靠前的弱密码开头（这类前缀在真实泄露事件中出现过几百万次）。攻击者的字典会完整包含它们，不需要任何技巧就能命中。'
    });
  }
  if (/(19|20)\d{2}$/.test(pwd) || (/(19|20)\d{2}/.test(pwd) && len <= 10)) {
    tips.push({
      level: 'warning',
      text: '包含年份数字（如 1995 / 2020）。年份通常是出生年或纪念年，攻击者会先把你和家人的出生年份、电话号码、门牌号等个人信息组合进字典，针对性极强。建议不要用任何与个人信息相关的数字。'
    });
  }
  if (/^\d+$/.test(pwd)) {
    tips.push({
      level: 'warning',
      text: '纯数字密码。即使有 10 位，攻击者用"纯数字掩码攻击"也只需跑几十亿次即可命中（GPU 几分钟）。数字在键盘上只有 10 个可选项，组合空间天然很小。'
    });
  }
  if (/^[a-z]+$/.test(pwd) && len >= 6) {
    tips.push({
      level: 'warning',
      text: '纯小写字母密码。攻击者的英文单词字典（含常见词+后缀变体）覆盖了几百万到上千万个组合，纯小写单词/拼音几乎全部在字典里。混入大写和数字即可大幅脱离字典覆盖范围。'
    });
  }

  // 6. 键盘序列
  const kb = ['qwerty','asdfgh','zxcvbn','1qaz','2wsx','3edc','qazwsx','1q2w3e4r','1q2w3e4r5t','qweasd','asdzxc','zxcasdqwe','poiuyt','lkjhg','mnbvc','qazxsw','edcrfv','rfvtgb','tgbyhn','yhnujm','ujmik,','ik,ol.','pl,okm','zaq12wsx','1qazxsw2','qweasdzxc','!@#$%','!@#$%^','!@#$%^&*'];
  for (const seq of kb) {
    if (lower.includes(seq)) {
      tips.push({
        level: 'warning',
        text: '包含键盘连续按键序列（' + seq + '）。这类"随手滑出来的"模式早被收入标准破解字典，攻击者无需猜测，直接查表即可。建议改用无规律的随机组合。'
      });
      break;
    }
  }

  // 7. 其他常见规律
  if (/^(.{3,})\1+$/.test(pwd) || /(.)\1{2,}/.test(pwd)) {
    tips.push({
      level: 'warning',
      text: '存在连续重复的字符块（如 ababab / aaa）。重复模式会显著压缩排列组合空间，且容易被"模式扩展规则"的字典覆盖。建议让每个位置的字符尽量互不相关。'
    });
  }
  if (pwd === pwd.toLowerCase() && /[a-z]/.test(pwd) && /[0-9]/.test(pwd) && /^(?=.*[a-z])(?=.*[0-9])/.test(pwd) && !/[A-Z!@#$%^&*]/.test(pwd)) {
    tips.push({
      level: 'warning',
      text: '纯小写字母+数字的组合（如 abc123 / mima123）虽然常见，但恰恰是字典攻击的高频命中区。建议把 1~2 个字母改为大写，并插入一个符号。'
    });
  }

  // 8. 通用建议（不罗列出处，直接给可执行动作）
  tips.push({ level: 'info', text: '最稳妥的做法：用密码管理器生成并保存一长串随机密码（20 位以上），每个网站使用不同密码。你只需记住一个主密码。' });
  tips.push({ level: 'info', text: '不要在不同网站复用同一密码：只要其中一个站点泄露，攻击者就会用这个密码去尝试你的其他所有账号（撞库）。' });
  tips.push({ level: 'info', text: '建议为重要账户开启多因素认证（MFA）：即使密码泄露，别人没有你的手机/安全密钥也无法登录。' });
  tips.push({ level: 'info', text: '设置"记忆式密码"的小技巧：想一句话（如"我2026年在上海买了3杯咖啡！"），取每个字的首字母+数字符号，得到类似 W2026nSHm3bKF! 的强密码，既好记又难猜。' });

  return tips;
}

window.buildSuggestions = buildSuggestions;
