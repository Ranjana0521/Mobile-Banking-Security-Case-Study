/**
 * SecureBank - Real-Time Cryptographic & Threat Defense Engine
 * Handles real-time typing events, risk scoring, entropy meters, OTP push notifications,
 * scrambled keypads, live AES-256-GCM / Scrypt inspections, and blockchain-style ledger verification.
 */

document.addEventListener('DOMContentLoaded', () => {
  initLiveClock();
  initPasswordEntropy();
  initTransferRiskEngine();
  initOtpDigitInputs();
  initPushNotificationBanner();
  initLandingSandbox();
  initLedgerViewer();
});

/* ==========================================================================
   1. Live Phone Clock
   ========================================================================== */
function initLiveClock() {
  const clockEl = document.getElementById('live-phone-time');
  if (!clockEl) return;
  const update = () => {
    const now = new Date();
    const hrs = String(now.getHours()).padStart(2, '0');
    const mins = String(now.getMinutes()).padStart(2, '0');
    clockEl.textContent = `${hrs}:${mins}`;
  };
  update();
  setInterval(update, 10000);
}

/* ==========================================================================
   2. Real-Time Password Entropy & Strength Meter (Typing Listener)
   ========================================================================== */
function initPasswordEntropy() {
  const loginPass = document.getElementById('password');
  const regPass = document.getElementById('reg-password');

  if (loginPass) {
    loginPass.addEventListener('input', () => evaluateEntropy(loginPass.value, 'entropy-fill', 'entropy-label', 'entropy-status'));
  }
  if (regPass) {
    regPass.addEventListener('input', () => evaluateEntropy(regPass.value, 'reg-entropy-fill', 'reg-entropy-label', 'reg-entropy-status'));
  }
}

function evaluateEntropy(password, fillId, labelId, statusId) {
  const fill = document.getElementById(fillId);
  const label = document.getElementById(labelId);
  const status = document.getElementById(statusId);
  if (!fill || !label || !status) return;

  if (!password) {
    fill.style.width = '0%';
    label.textContent = 'Entropy: 0 bits';
    status.textContent = 'Enter password';
    status.style.color = 'var(--text-muted)';
    return;
  }

  // Calculate pool size based on character variety
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 32;

  // Shannon Entropy: E = L * log2(R)
  const entropy = Math.round(password.length * (pool > 0 ? Math.log2(pool) : 0));
  label.textContent = `Entropy: ${entropy} bits (Scrypt KDF Input)`;

  // Percentage up to 80 bits (NIST SP 800-63B benchmark)
  const pct = Math.min(100, Math.round((entropy / 80) * 100));
  fill.style.width = `${pct}%`;

  if (entropy < 35) {
    fill.style.background = 'var(--neon-red)';
    status.textContent = 'Weak (Prone to dictionary attack)';
    status.style.color = 'var(--neon-red)';
  } else if (entropy < 60) {
    fill.style.background = 'var(--neon-amber)';
    status.textContent = 'Moderate (Protected by Scrypt memory-cost)';
    status.style.color = 'var(--neon-amber)';
  } else {
    fill.style.background = 'var(--neon-green)';
    status.textContent = 'High Security (ASIC/GPU resistant)';
    status.style.color = 'var(--neon-green)';
  }
}

/* ==========================================================================
   3. Real-Time Transfer Risk Scoring Engine (Typing Listener)
   ========================================================================== */
function initTransferRiskEngine() {
  const amountInput = document.getElementById('amount');
  const recipientInput = document.getElementById('recipient');

  if (!amountInput) return;

  const evaluateRisk = () => {
    const amt = parseFloat(amountInput.value) || 0;
    const recipient = (recipientInput ? recipientInput.value : '').trim();
    const balance = window.CURRENT_BALANCE || 5000;

    const pill = document.getElementById('risk-tier-pill');
    const fill = document.getElementById('risk-bar-fill');
    const exp = document.getElementById('risk-explanation');
    if (!pill || !fill || !exp) return;

    if (amt <= 0) {
      pill.className = 'risk-tier-pill tier-low';
      pill.textContent = 'STANDBY (0/100)';
      fill.style.width = '5%';
      fill.className = 'risk-bar-fill fill-low';
      exp.textContent = 'Enter recipient and amount to calculate real-time transfer risk score.';
      return;
    }

    let score = 10;
    let reasons = [];

    // Factor 1: Percentage of available balance
    const ratio = amt / balance;
    if (ratio > 0.8) {
      score += 45;
      reasons.push('Transfer exceeds 80% of available liquid balance');
    } else if (ratio > 0.5) {
      score += 25;
      reasons.push('Transfer exceeds 50% of available balance');
    }

    // Factor 2: High Amount Threshold
    if (amt >= 2000) {
      score += 35;
      reasons.push('Amount ≥ ₹2,000 triggers strict demo risk review rule');
    }

    // Factor 3: Recipient check
    if (recipient.toLowerCase().includes('unknown') || recipient.length > 25) {
      score += 15;
      reasons.push('Unverified recipient format');
    }

    // Factor 4: Device Compromise (if simulated malware active)
    if (window.MALWARE_SIMULATED) {
      score += 40;
      reasons.push('Runtime device integrity flag: Active malware / Accessibility hook');
    }

    score = Math.min(100, score);
    fill.style.width = `${score}%`;

    if (score < 40) {
      pill.className = 'risk-tier-pill tier-low';
      pill.textContent = `LOW RISK (${score}/100)`;
      fill.className = 'risk-bar-fill fill-low';
      exp.textContent = reasons.length ? reasons.join('. ') + '.' : 'Normal transaction velocity. Standard dynamic HMAC-SHA256 OTP confirmation required.';
    } else if (score < 75) {
      pill.className = 'risk-tier-pill tier-med';
      pill.textContent = `ELEVATED RISK (${score}/100)`;
      fill.className = 'risk-bar-fill fill-med';
      exp.textContent = reasons.join('. ') + '. Requires step-up OTP authentication.';
    } else {
      pill.className = 'risk-tier-pill tier-high';
      pill.textContent = `HIGH RISK (${score}/100)`;
      fill.className = 'risk-bar-fill fill-high';
      exp.textContent = reasons.join('. ') + '. Alert: transfer will trigger additional risk screening!';
    }
  };

  amountInput.addEventListener('input', evaluateRisk);
  if (recipientInput) recipientInput.addEventListener('input', evaluateRisk);
}

/* Quick Helpers for Transfer Form */
function setRecipient(name) {
  const r = document.getElementById('recipient');
  if (r) {
    r.value = name;
    r.dispatchEvent(new Event('input'));
  }
}

function addAmount(val) {
  const a = document.getElementById('amount');
  if (a) {
    const cur = parseFloat(a.value) || 0;
    a.value = (cur + val).toFixed(2);
    a.dispatchEvent(new Event('input'));
  }
}

function setAmount(val) {
  const a = document.getElementById('amount');
  if (a) {
    a.value = parseFloat(val).toFixed(2);
    a.dispatchEvent(new Event('input'));
  }
}

function scrollToTransfer() {
  const p = document.getElementById('transfer-panel-section');
  if (p) p.scrollIntoView({ behavior: 'smooth' });
}

/* ==========================================================================
   4. OTP Digit Inputs & Autofill Navigation
   ========================================================================== */
function initOtpDigitInputs() {
  const digits = [
    document.getElementById('otp-d1'),
    document.getElementById('otp-d2'),
    document.getElementById('otp-d3'),
    document.getElementById('otp-d4'),
    document.getElementById('otp-d5'),
    document.getElementById('otp-d6')
  ];

  if (!digits[0]) return;

  const fullInput = document.getElementById('full-otp-input');

  const updateFullOtp = () => {
    const code = digits.map(d => d.value).join('');
    if (fullInput) fullInput.value = code;
  };

  digits.forEach((digit, idx) => {
    digit.addEventListener('input', (e) => {
      const val = digit.value.replace(/[^0-9]/g, '');
      digit.value = val ? val[0] : '';
      updateFullOtp();
      if (digit.value && idx < 5) {
        digits[idx + 1].focus();
      }
    });

    digit.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !digit.value && idx > 0) {
        digits[idx - 1].focus();
      }
    });

    digit.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasteData = (e.clipboardData || window.clipboardData).getData('text').trim();
      const numMatches = pasteData.match(/\d/g);
      if (numMatches && numMatches.length >= 6) {
        numMatches.slice(0, 6).forEach((n, i) => {
          if (digits[i]) digits[i].value = n;
        });
        updateFullOtp();
        digits[5].focus();
      }
    });
  });

  // Countdown timer for pending OTP
  if (window.PENDING_TRANSFER_EXISTS && window.PENDING_EXPIRES_AT) {
    const countdownEl = document.getElementById('otp-countdown-text');
    const interval = setInterval(() => {
      const now = Date.now() / 1000;
      const left = Math.max(0, Math.round(window.PENDING_EXPIRES_AT - now));
      const mins = String(Math.floor(left / 60)).padStart(2, '0');
      const secs = String(left % 60).padStart(2, '0');
      if (countdownEl) countdownEl.textContent = `${mins}:${secs}`;
      if (left <= 0) {
        clearInterval(interval);
        if (countdownEl) countdownEl.textContent = 'EXPIRED';
      }
    }, 1000);
  }
}

/* ==========================================================================
   5. Simulated Mobile Push Notification for OTP
   ========================================================================== */
function initPushNotificationBanner() {
  if (!window.PENDING_TRANSFER_EXISTS) return;

  // Fetch the active OTP from backend
  fetch('/api/otp/current')
    .then(r => r.json())
    .then(data => {
      if (data && data.active && data.otp) {
        const banner = document.getElementById('push-notification-banner');
        const msg = document.getElementById('push-notification-msg');
        const timerSeconds = document.getElementById('push-timer-seconds');
        const btnAutofill = document.getElementById('btn-autofill-otp');

        if (banner && msg) {
          msg.innerHTML = `Your transfer OTP for <strong>₹${data.amount.toFixed(2)}</strong> to <strong>${data.recipient}</strong> is <strong style="color:var(--neon-green);font-size:15px;letter-spacing:0.15em;">${data.otp}</strong>.`;
          banner.style.display = 'block';

          let secondsLeft = data.expires_in || 180;
          if (timerSeconds) timerSeconds.textContent = secondsLeft;

          const timer = setInterval(() => {
            secondsLeft--;
            if (timerSeconds) timerSeconds.textContent = Math.max(0, secondsLeft);
            if (secondsLeft <= 0) {
              clearInterval(timer);
              banner.style.display = 'none';
            }
          }, 1000);

          if (btnAutofill) {
            btnAutofill.onclick = () => {
              autofillOtp(data.otp);
              banner.style.opacity = '0.5';
              btnAutofill.innerHTML = '<span>✓ Auto-Filled</span>';
            };
          }
        }
      }
    })
    .catch(() => {});
}

function autofillOtp(otpStr) {
  const digits = [
    document.getElementById('otp-d1'),
    document.getElementById('otp-d2'),
    document.getElementById('otp-d3'),
    document.getElementById('otp-d4'),
    document.getElementById('otp-d5'),
    document.getElementById('otp-d6')
  ];
  const fullInput = document.getElementById('full-otp-input');

  if (otpStr && otpStr.length >= 6) {
    for (let i = 0; i < 6; i++) {
      if (digits[i]) digits[i].value = otpStr[i];
    }
    if (fullInput) fullInput.value = otpStr;
    if (digits[5]) digits[5].focus();
  }
}

/* ==========================================================================
   6. Anti-Keylogger Scrambled Keypad
   ========================================================================== */
function toggleVirtualKeypad() {
  const box = document.getElementById('virtual-keypad-box');
  if (!box) return;
  if (box.style.display === 'none' || !box.style.display) {
    box.style.display = 'block';
    renderScrambledDigits('keypad-digits', 'password');
  } else {
    box.style.display = 'none';
  }
}

function toggleScrambledPadInTransfer() {
  const chk = document.getElementById('chk-scrambled-keypad');
  const box = document.getElementById('transfer-scrambled-box');
  if (!box || !chk) return;
  if (chk.checked) {
    box.style.display = 'block';
    renderScrambledDigits('transfer-keypad-digits', 'amount');
  } else {
    box.style.display = 'none';
  }
}

function shuffleKeypad() {
  renderScrambledDigits('keypad-digits', 'password');
}

function shuffleTransferKeypad() {
  renderScrambledDigits('transfer-keypad-digits', 'amount');
}

function renderScrambledDigits(containerId, targetInputId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const numbers = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  // Fisher-Yates shuffle
  for (let i = numbers.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [numbers[i], numbers[j]] = [numbers[j], numbers[i]];
  }

  container.innerHTML = '';
  numbers.forEach(num => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'keypad-key';
    btn.textContent = num;
    btn.onclick = () => {
      const target = document.getElementById(targetInputId);
      if (target) {
        target.value += num;
        target.dispatchEvent(new Event('input'));
      }
    };
    container.appendChild(btn);
  });

  // Add Backspace key
  const delBtn = document.createElement('button');
  delBtn.type = 'button';
  delBtn.className = 'keypad-key';
  delBtn.style.color = 'var(--neon-red)';
  delBtn.innerHTML = '⌫';
  delBtn.onclick = () => {
    const target = document.getElementById(targetInputId);
    if (target && target.value.length > 0) {
      target.value = target.value.slice(0, -1);
      target.dispatchEvent(new Event('input'));
    }
  };
  container.appendChild(delBtn);

  // Add Clear key
  const clrBtn = document.createElement('button');
  clrBtn.type = 'button';
  clrBtn.className = 'keypad-key';
  clrBtn.style.color = 'var(--neon-amber)';
  clrBtn.innerHTML = 'C';
  clrBtn.onclick = () => {
    const target = document.getElementById(targetInputId);
    if (target) {
      target.value = '';
      target.dispatchEvent(new Event('input'));
    }
  };
  container.appendChild(clrBtn);
}

/* ==========================================================================
   7. Threat Defense Simulation Lab (Pillars 1, 2, 3)
   ========================================================================== */

/* Vector 1: Mobile Malware & Trojan Injection */
window.MALWARE_SIMULATED = false;

function simulateMalwareAttack() {
  window.MALWARE_SIMULATED = true;
  const telStatus = document.getElementById('telemetry-device-status');
  const logBox = document.getElementById('malware-defense-log');
  const chkKeypad = document.getElementById('chk-scrambled-keypad');

  if (telStatus) {
    telStatus.innerHTML = '<span class="status-dot" style="background:var(--neon-red);"></span> COMPROMISED (HOOK/OVERLAY DETECTED)';
    telStatus.className = 'telemetry-value text-red';
  }

  // Force anti-keylogger scrambled keypad on in transfer
  if (chkKeypad) {
    chkKeypad.checked = true;
    toggleScrambledPadInTransfer();
  }

  if (logBox) {
    logBox.innerHTML = `
      <div class="log-line text-red" style="font-weight:700;">[THREAT DETECTED] Accessibility Service Hook Attempt from process PID: 4092 (Trojan: TeaBot.v2)</div>
      <div class="log-line text-amber">[RASP ACTIVATED] Overlay injection neutralized. Virtual coordinates scrambled.</div>
      <div class="log-line text-cyan">[POLICY ENFORCED] Device Trust: 15/100. High-value transactions frozen. Anti-keylogger randomized pad activated.</div>
    `;
  }

  // Re-trigger transfer risk evaluation
  const amtInput = document.getElementById('amount');
  if (amtInput) amtInput.dispatchEvent(new Event('input'));
}

function resetMalwareDefense() {
  window.MALWARE_SIMULATED = false;
  const telStatus = document.getElementById('telemetry-device-status');
  const logBox = document.getElementById('malware-defense-log');

  if (telStatus) {
    telStatus.innerHTML = '<span class="status-dot pulse-green"></span> HARDENED (NO ROOT / NO HOOKS)';
    telStatus.className = 'telemetry-value text-green';
  }

  if (logBox) {
    logBox.innerHTML = `
      <div class="log-line text-green">[RASP RESTORED] Device environment verified clean. No active hooks. Integrity: 100%.</div>
    `;
  }

  const amtInput = document.getElementById('amount');
  if (amtInput) amtInput.dispatchEvent(new Event('input'));
}

/* Vector 2: Phishing URL & Smishing Link Scanner */
function testSampleUrl(url) {
  const input = document.getElementById('phishing-url-input');
  if (input) {
    input.value = url;
    scanPhishingUrl();
  }
}

function scanPhishingUrl() {
  const input = document.getElementById('phishing-url-input');
  const resultsBox = document.getElementById('phishing-scanner-results');
  if (!input || !resultsBox) return;

  const url = input.value.trim();
  if (!url) return;

  resultsBox.innerHTML = '<div class="log-line text-cyan">Analyzing URL domain entropy, homoglyphs, and SSL fingerprint...</div>';

  fetch('/api/threat-defense/phishing-scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
  .then(r => r.json())
  .then(data => {
    let html = '';
    if (data.is_phishing) {
      html += `<div class="log-line text-red" style="font-weight:700;">🚨 [PHISHING DETECTED] Threat Score: ${data.score}/100 - ${data.verdict}</div>`;
      data.threats.forEach(t => {
        html += `<div class="log-line text-amber">  • Alert: ${t}</div>`;
      });
      html += `<div class="log-line text-cyan">  • Mutual Auth Defense: Missing user personal security secret ("${document.getElementById('telemetry-phrase')?.textContent || 'Emerald Falcon'}"). Domain rejected.</div>`;
    } else {
      html += `<div class="log-line text-green" style="font-weight:700;">✓ [VERIFIED OFFICIAL DOMAIN] Threat Score: ${data.score}/100</div>`;
      html += `<div class="log-line text-cyan">  • SSL Pinning: SHA-256 Public Key Pinning matched official SecureBank certificate.</div>`;
      html += `<div class="log-line text-green">  • Anti-Phishing Secret Phrase validated with genuine backend. Safe to proceed.</div>`;
    }
    resultsBox.innerHTML = html;
  })
  .catch(() => {
    resultsBox.innerHTML = '<div class="log-line text-red">Scan request failed. Check server connection.</div>';
  });
}

/* Vector 3: Ciphertext Bit-Flipping & Tamper Detection */
function simulateCiphertextTamper() {
  const logBox = document.getElementById('tamper-defense-log');
  if (!logBox) return;

  logBox.innerHTML = '<div class="log-line text-cyan">Executing 1-bit tampering on encrypted transaction blob...</div>';

  fetch('/api/crypto/simulate-tamper', { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      let html = '';
      html += `<div class="log-line text-amber">[1. ORIGINAL CIPHERTEXT] ${data.original_hex.substring(0, 36)}... (Valid Tag)</div>`;
      html += `<div class="log-line text-red">[2. TAMPERED 1-BIT FLIP] ${data.tampered_hex.substring(0, 36)}... (Bit 0 altered)</div>`;
      html += `<div class="log-line text-red" style="font-weight:700;">[3. AES-256-GCM RESULT] ${data.exception}: ${data.explanation}</div>`;
      html += `<div class="log-line text-green">[4. INTEGRITY PROOF] Authenticated encryption guarantees that any unauthorized modification to SQLite database is detected and rejected mathematically!</div>`;
      logBox.innerHTML = html;
    })
    .catch(() => {
      logBox.innerHTML = '<div class="log-line text-red">Tamper test failed.</div>';
    });
}

/* ==========================================================================
   8. Cryptographic Inspector Deep-Dive (AES-256-GCM & Scrypt Live)
   ========================================================================== */
function runLiveAesEncrypt() {
  const text = document.getElementById('aes-plaintext-input').value;
  fetch('/api/crypto/aes-simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ plaintext: text })
  })
  .then(r => r.json())
  .then(d => {
    document.getElementById('aes-out-nonce').textContent = d.nonce_hex;
    document.getElementById('aes-out-ct').textContent = d.ciphertext_hex;
    document.getElementById('aes-out-tag').textContent = d.tag_hex;
  });
}

function runLiveScryptDerive() {
  const pass = document.getElementById('scrypt-pass-input').value;
  const salt = document.getElementById('scrypt-salt-input').value;
  fetch('/api/crypto/scrypt-simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: pass, salt_hex: salt })
  })
  .then(r => r.json())
  .then(d => {
    document.getElementById('scrypt-out-hash').textContent = `${d.derived_key_hex} (${d.time_ms}ms)`;
  });
}

/* ==========================================================================
   9. Tamper-Evident SHA-256 Chained Audit Ledger
   ========================================================================== */
function initLedgerViewer() {
  const container = document.getElementById('ledger-blocks-container');
  if (!container) return;

  fetch('/api/ledger/blocks')
    .then(r => r.json())
    .then(blocks => {
      if (!blocks || !blocks.length) {
        container.innerHTML = '<div class="ledger-loading">No transactions recorded yet in ledger chain.</div>';
        return;
      }
      container.innerHTML = '';
      blocks.forEach(b => {
        const card = document.createElement('div');
        card.className = 'ledger-block-card';
        card.innerHTML = `
          <div class="block-header-row">
            <span class="block-index-badge">BLOCK #${b.index}</span>
            <span class="block-time">${b.timestamp || 'GENESIS'}</span>
          </div>
          <div class="block-hash-grid">
            <div class="hash-row">
              <span class="hash-label">Previous Block Hash (SHA-256)</span>
              <span class="hash-value">${b.previous_hash}</span>
            </div>
            <div class="hash-row">
              <span class="hash-label">Current Block Hash (SHA-256)</span>
              <span class="hash-value hash-current">${b.block_hash}</span>
            </div>
            <div class="hash-row">
              <span class="hash-label">Encrypted Payload Preview</span>
              <span class="hash-value text-muted">${b.payload_preview}</span>
            </div>
          </div>
        `;
        container.appendChild(card);
      });
    })
    .catch(() => {
      container.innerHTML = '<div class="ledger-loading text-red">Failed to load ledger blocks.</div>';
    });
}

function verifyLedgerIntegrity() {
  const statusBanner = document.getElementById('ledger-verify-status');
  const statusText = document.getElementById('ledger-status-text');
  if (!statusText) return;

  statusText.textContent = 'Recalculating SHA-256 cryptographic chain hashes...';

  fetch('/api/ledger/verify')
    .then(r => r.json())
    .then(data => {
      if (data.valid) {
        statusBanner.style.background = 'rgba(0, 229, 153, 0.12)';
        statusBanner.style.borderColor = 'rgba(0, 229, 153, 0.4)';
        statusText.innerHTML = `✓ <strong>100% Cryptographic Integrity Verified</strong>: ${data.total_blocks} blocks re-hashed. Zero unauthorized injections or modifications detected.`;
      } else {
        statusBanner.style.background = 'rgba(255, 51, 102, 0.15)';
        statusBanner.style.borderColor = 'rgba(255, 51, 102, 0.4)';
        statusText.innerHTML = `⚠️ <strong>INTEGRITY BREACH DETECTED!</strong> Block #${data.broken_at} failed SHA-256 hash chaining verification!`;
      }
    })
    .catch(() => {
      statusText.textContent = 'Integrity verification query failed.';
    });
}

/* ==========================================================================
   10. Landing Page Quick Crypto Sandbox
   ========================================================================== */
function initLandingSandbox() {
  const runBtn = document.getElementById('btn-run-sandbox');
  const input = document.getElementById('sandbox-input');
  if (!runBtn || !input) return;

  const run = () => {
    const val = input.value || 'SecureBankDemo';
    fetch('/api/crypto/aes-simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plaintext: val })
    })
    .then(r => r.json())
    .then(d => {
      document.getElementById('sb-nonce').textContent = d.nonce_hex;
      document.getElementById('sb-tag').textContent = d.tag_hex;
    });

    fetch('/api/crypto/scrypt-simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: val, salt_hex: '0102030405060708090a0b0c0d0e0f10' })
    })
    .then(r => r.json())
    .then(d => {
      document.getElementById('sb-scrypt').textContent = d.derived_key_hex;
    });
  };

  runBtn.addEventListener('click', run);
  input.addEventListener('input', debounce(run, 400));
  run();
}

function debounce(fn, delay) {
  let timer;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

/* ==========================================================================
   11. Operations Tabs & Modals
   ========================================================================== */
function switchOpsTab(tabId) {
  document.querySelectorAll('.ops-tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-target') === tabId);
  });
  document.querySelectorAll('.ops-tab-content').forEach(content => {
    content.classList.toggle('active', content.id === tabId);
  });
}

function togglePasswordVisibility(fieldId) {
  const input = document.getElementById(fieldId);
  if (!input) return;
  input.type = input.type === 'password' ? 'text' : 'password';
}

function toggleBalanceMask() {
  const bal = document.getElementById('phone-balance-display');
  const num = document.getElementById('card-num-masked');
  if (!bal) return;
  if (bal.textContent.includes('•')) {
    bal.textContent = (window.CURRENT_BALANCE || 0).toLocaleString('en-IN', { minimumFractionDigits: 2 });
    if (num) num.textContent = '•••• •••• •••• 2048';
  } else {
    bal.textContent = '••••••';
    if (num) num.textContent = '•••• •••• •••• ••••';
  }
}

function openDepositDemoModal() {
  const m = document.getElementById('deposit-modal');
  if (m) m.style.display = 'grid';
}

function closeDepositModal() {
  const m = document.getElementById('deposit-modal');
  if (m) m.style.display = 'none';
}

function toggleSecurityShieldModal() {
  switchOpsTab('tab-threat-lab');
}

function inspectTxCrypto(recipient, amount, time, cipherHex) {
  const modal = document.getElementById('cipher-inspect-modal');
  const jsonBox = document.getElementById('modal-decrypted-json');
  const hexBox = document.getElementById('modal-raw-hex');
  if (!modal || !jsonBox || !hexBox) return;

  jsonBox.textContent = JSON.stringify({ recipient: recipient, amount: parseFloat(amount), time: time }, null, 2);
  hexBox.textContent = cipherHex || '12-byte Nonce (0x7e2a...) + AES-256 Ciphertext + 16-byte GCM GHASH Tag';
  modal.style.display = 'grid';
}

function closeCipherModal() {
  const m = document.getElementById('cipher-inspect-modal');
  if (m) m.style.display = 'none';
}
