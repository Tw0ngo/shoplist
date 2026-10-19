// Password rules, used by the server (require) and by the forms (checklist that ticks off while typing)
(function (root) {
  const COMMON = ['password', 'passwort', 'password1', 'passwort1', '12345678', '123456789', '1234567890', '87654321',
    '11111111', '00000000', 'qwertz123', 'qwerty123', 'qwertzuiop', 'qwertyuiop', 'asdfghjk', 'abcdefgh', 'iloveyou',
    'ichliebedich', 'einkaufen', 'shoplist', 'shopping', 'einkaufsliste', 'hallo123', 'letmein1', 'welcome1', 'sommer2026'];

  // [text key, test(password, user name)]
  const RULES = [
    ['pw.ruleLength', pw => pw.length >= 8 && pw.length <= 200],
    ['pw.ruleName', (pw, name) => { const u = String(name || '').toLowerCase(); return u.length < 2 || !pw.toLowerCase().includes(u); }],
    ['pw.ruleCommon', pw => !COMMON.includes(pw.toLowerCase()) && !/^(.)\1+$/.test(pw)],
  ];
  const pwOk = (pw, name) => RULES.every(([, test]) => test(String(pw), name));

  if (typeof module !== 'undefined') { module.exports = { pwOk }; return; }

  // <ul> under a password field; the rules turn green once met (nothing is marked before typing starts)
  function pwChecklist(input, name = () => '') {
    const ul = document.createElement('ul');
    ul.className = 'pwrules';
    const items = RULES.map(([key, test]) => {
      const li = document.createElement('li');
      const span = document.createElement('span');
      span.dataset.t = key;
      span.textContent = t(key);
      li.append(span);
      ul.append(li);
      return [li, test];
    });
    const update = () => {
      for (const [li, test] of items) {
        li.classList.toggle('ok', !!input.value && test(input.value, name()));
        li.classList.toggle('bad', !!input.value && !test(input.value, name()));
      }
    };
    input.addEventListener('input', update);
    ul.update = update;
    return ul;
  }
  Object.assign(root, { pwOk, pwChecklist });
})(this);
