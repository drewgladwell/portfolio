function analyzeComplexity(password, personalFields) {
  const checks = [
    ['Length 8+', /.{8,}/.test(password)],
    ['Has uppercase', /[A-Z]/.test(password)],
    ['Has lowercase', /[a-z]/.test(password)],
    ['Has digit', /[0-9]/.test(password)],
    ['Has special character (!@#$%^&*)', /[!@#$%^&*]/.test(password)]
  ];
  const personal = personalFields.some(value => value.length > 0 && password.toLowerCase().includes(value.toLowerCase()));
  return { checks, score: checks.filter(([, passed]) => passed).length, personal };
}
function ratePassword(score, count) {
  const adjusted = count > 100000 ? 0 : count > 0 ? score - 2 : score;
  const rating = adjusted <= 0 ? 'Critically Weak' : adjusted <= 2 ? 'Weak' : adjusted === 3 ? 'Fair' : adjusted === 4 ? 'Strong' : 'Very Strong';
  return { score: adjusted, rating };
}
async function checkBreach(password) {
  const bytes = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  const hash = Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  const response = await fetch(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
    headers: { 'Add-Padding': 'true' }, signal: AbortSignal.timeout(15000), credentials: 'omit', referrerPolicy: 'no-referrer'
  });
  if (!response.ok) throw new Error('Breach lookup failed');
  const text = await response.text();
  let count = 0;
  for (const line of text.trim().split(/\r?\n/)) {
    const match = /^([A-F0-9]{35}):(\d+)$/.exec(line);
    if (!match) throw new Error('Invalid breach response');
    if (match[1] === hash.slice(5)) count = Number(match[2]);
  }
  return count;
}
if (typeof document !== 'undefined') {
  const form = document.getElementById('analyzer');
  const passwordInput = document.getElementById('password');
  const status = document.getElementById('status');
  const submit = document.getElementById('analyze');
  const visibility = document.getElementById('visibility');
  visibility.addEventListener('click', () => {
    const show = passwordInput.type === 'password';
    passwordInput.type = show ? 'text' : 'password';
    visibility.textContent = show ? 'Hide' : 'Show';
    visibility.setAttribute('aria-pressed', String(show));
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const password = passwordInput.value;
    const analysis = analyzeComplexity(password, ['name', 'username', 'birth-year'].map(id => document.getElementById(id).value));
    submit.disabled = true;
    Array.from(form.elements).forEach(element => { element.disabled = true; });
    document.getElementById('results').hidden = true;
    status.textContent = 'Checking complexity and known breach data…';
    let count = 0;
    let verified = true;
    try { count = await checkBreach(password); } catch { verified = false; }
    const final = ratePassword(analysis.score, count);
    document.getElementById('rating').textContent = `${final.rating}${verified ? '' : ' (provisional)'}`;
    document.getElementById('score').textContent = `Complexity: ${analysis.score}/5 · ${verified ? 'Final' : 'Provisional'} score: ${final.score}/5`;
    document.getElementById('checks').replaceChildren(...analysis.checks.map(([label, passed]) => {
      const li = document.createElement('li');
      li.textContent = `${passed ? '✓' : '✕'} ${label}: ${passed ? 'Pass' : 'Fail'}`;
      return li;
    }));
    document.getElementById('personal-warning').hidden = !analysis.personal;
    document.getElementById('breach-result').textContent = !verified ? 'Breach check unavailable. This rating uses complexity checks only. Try again to include breach data.' : count > 0 ? `This password appears ${count.toLocaleString()} times in the Pwned Passwords dataset.` : 'This password was not found in the Pwned Passwords dataset. This does not guarantee it is safe.';
    document.getElementById('results').hidden = false;
    status.textContent = verified ? 'Analysis complete.' : 'Analysis complete; breach check unavailable.';
    Array.from(form.elements).forEach(element => { element.disabled = false; });
  });
}
