/**
 * CIS Audit Agent - Enterprise Dashboard & AI Assistant Script
 */

document.addEventListener('DOMContentLoaded', () => {
  let currentAuditData = null;

  // DOM Elements
  const runAuditBtn = document.getElementById('runAuditBtn');
  const btnSpinner = document.getElementById('btnSpinner');
  const btnIcon = document.getElementById('btnIcon');
  const btnText = document.getElementById('btnText');
  
  const targetInput = document.getElementById('targetInput');
  const transportSelect = document.getElementById('transportSelect');
  
  const scoreText = document.getElementById('scoreText');
  const scoreSubtitle = document.getElementById('scoreSubtitle');
  const ringFill = document.getElementById('ringFill');
  const gradeBadge = document.getElementById('gradeBadge');
  
  const passCount = document.getElementById('passCount');
  const failCount = document.getElementById('failCount');
  const unknownCount = document.getElementById('unknownCount');
  
  const fixListContainer = document.getElementById('fixListContainer');
  const matrixTableBody = document.getElementById('matrixTableBody');
  const terminalOutput = document.getElementById('terminalOutput');
  const ruleSearchInput = document.getElementById('ruleSearchInput');
  
  const chatMessages = document.getElementById('chatMessages');
  const chatForm = document.getElementById('chatForm');
  const chatInput = document.getElementById('chatInput');
  
  // Modal Elements
  const evidenceModal = document.getElementById('evidenceModal');
  const closeModalBtn = document.getElementById('closeModalBtn');
  const modalRuleId = document.getElementById('modalRuleId');
  const modalCmd = document.getElementById('modalCmd');
  const modalVerdict = document.getElementById('modalVerdict');
  const modalRawOutput = document.getElementById('modalRawOutput');

  // Fetch Initial Report
  fetchReport();

  // Tab Switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      
      btn.classList.add('active');
      const tabId = btn.getAttribute('data-tab');
      document.getElementById(tabId).classList.add('active');
    });
  });

  // Search Filter
  ruleSearchInput.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase();
    if (!currentAuditData) return;

    filterFindings(query);
  });

  // Run Audit Event
  runAuditBtn.addEventListener('click', async () => {
    const target = targetInput.value;
    const transport = transportSelect.value;

    setLoading(true);

    try {
      const response = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, transport })
      });

      const data = await response.json();
      if (response.ok) {
        currentAuditData = data;
        renderDashboard(data);
        appendBotMessage(`✅ **Audit Execution Complete for \`${target}\`!** Evaluated ${data.summary.total_checks} CIS rules (${data.summary.pass_count} Passed, ${data.summary.fail_count} Failed).`);
      } else {
        alert(data.error || 'Audit execution failed.');
      }
    } catch (err) {
      alert('Error connecting to server: ' + err.message);
    } finally {
      setLoading(false);
    }
  });

  // Chat Form Submit
  chatForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const message = chatInput.value.trim();
    if (!message) return;

    appendUserMessage(message);
    chatInput.value = '';

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message })
      });

      const data = await response.json();
      if (response.ok) {
        appendBotMessage(data.reply);
      } else {
        appendBotMessage("⚠️ Sorry, I encountered an error answering your question.");
      }
    } catch (err) {
      appendBotMessage("⚠️ Connection error: " + err.message);
    }
  });

  // Chip Clicks
  document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const query = chip.getAttribute('data-query');
      chatInput.value = query;
      chatForm.dispatchEvent(new Event('submit'));
    });
  });

  // Close Modal
  closeModalBtn.addEventListener('click', () => {
    evidenceModal.classList.add('hidden');
  });

  // Fetch Report API
  async function fetchReport() {
    try {
      const response = await fetch('/api/report');
      if (response.ok) {
        const data = await response.json();
        currentAuditData = data;
        renderDashboard(data);
      }
    } catch (err) {
      console.log('No report yet');
    }
  }

  // Render Dashboard Function
  function renderDashboard(data) {
    const summary = data.summary || {};
    const total = summary.total_checks || 10;
    const passes = summary.pass_count || 0;
    const fails = summary.fail_count || 0;
    const unknowns = summary.unknown_count || 0;

    passCount.textContent = passes;
    failCount.textContent = fails;
    unknownCount.textContent = unknowns;

    // Calculate Ring Score
    const scorePct = Math.round((passes / total) * 100);
    scoreText.textContent = `${scorePct}%`;

    // 251.2 is max stroke-dasharray for r=40
    const offset = 251.2 - (251.2 * scorePct) / 100;
    ringFill.style.strokeDashoffset = offset;

    if (scorePct >= 90) {
      gradeBadge.textContent = 'GRADE A+';
      gradeBadge.className = 'grade-badge grade-a';
      scoreSubtitle.textContent = 'All Security Controls Passing';
    } else if (scorePct >= 60) {
      gradeBadge.textContent = 'GRADE C';
      gradeBadge.className = 'grade-badge grade-f';
      scoreSubtitle.textContent = `${fails} Failures Detected`;
    } else {
      gradeBadge.textContent = 'GRADE F';
      gradeBadge.className = 'grade-badge grade-f';
      scoreSubtitle.textContent = `${fails} Critical Failures Detected`;
    }

    // Render Fix Stack
    renderFixStack(data.fix_list || []);

    // Render Matrix Table
    renderMatrixTable(data.findings || []);

    // Render Terminal Log Output
    renderTerminalLogs(data.raw_evidence || {});
  }

  // Render Fix Cards Stack
  function renderFixStack(fixList) {
    if (fixList.length === 0) {
      fixListContainer.innerHTML = `
        <div class="empty-placeholder" style="color: #10b981;">
          🎉 <strong>Zero Vulnerabilities Found!</strong><br>
          Host complies with all evaluated CIS Benchmark rules.
        </div>`;
      return;
    }

    fixListContainer.innerHTML = fixList.map(item => `
      <div class="fix-card-item">
        <div class="fix-card-top">
          <span class="fix-p-badge">PRIORITY ${item.priority} • ${item.rule_id}</span>
          <span class="fix-cat-badge">${escapeHtml(item.category)}</span>
        </div>
        <div class="fix-headline">${escapeHtml(item.finding)}</div>
        <div class="fix-why-box">💡 <strong>Why It Matters:</strong> ${escapeHtml(item.why_it_matters)}</div>
        <div class="command-snippet-box">
          <code>${escapeHtml(item.fix_command)}</code>
          <button class="copy-icon-btn" onclick="copyCommand('${escapeJs(item.fix_command)}', this)">📋 Copy Fix</button>
        </div>
      </div>
    `).join('');
  }

  // Render Compliance Matrix Table
  function renderMatrixTable(findings) {
    if (findings.length === 0) {
      matrixTableBody.innerHTML = `<tr><td colspan="5" class="empty-cell">No findings available.</td></tr>`;
      return;
    }

    matrixTableBody.innerHTML = findings.map(f => {
      let tagClass = 'tag-pass';
      let icon = '🟢 PASS';
      if (f.status === 'FAIL') {
        tagClass = 'tag-fail';
        icon = '🔴 FAIL';
      } else if (f.status === 'UNKNOWN') {
        tagClass = 'tag-unknown';
        icon = '🟡 UNKNOWN';
      }

      return `
        <tr>
          <td><code>${escapeHtml(f.rule_id)}</code></td>
          <td><strong>${escapeHtml(f.title)}</strong></td>
          <td><span class="verdict-tag ${tagClass}">${icon}</span></td>
          <td><code>${escapeHtml(f.evidence.slice(0, 75))}</code></td>
          <td><button class="chip" onclick="inspectRule('${f.rule_id}')">🔍 Inspect</button></td>
        </tr>
      `;
    }).join('');
  }

  // Render Terminal Execution Logs
  function renderTerminalLogs(rawEv) {
    let logs = [];
    for (const [key, val] of Object.entries(rawEv)) {
      logs.push(`[$] ${val.command}`);
      if (val.stdout) logs.push(`stdout: ${val.stdout}`);
      if (val.stderr) logs.push(`stderr: ${val.stderr}`);
      logs.push(`exit_code: ${val.exit_code}\n`);
    }
    terminalOutput.textContent = logs.join('\n');
  }

  // Filter Findings
  function filterFindings(query) {
    const findings = currentAuditData.findings || [];
    const filtered = findings.filter(f => 
      f.rule_id.toLowerCase().includes(query) || 
      f.title.toLowerCase().includes(query) ||
      f.evidence.toLowerCase().includes(query)
    );
    renderMatrixTable(filtered);
  }

  // Inspect Rule Modal
  window.inspectRule = function(ruleId) {
    if (!currentAuditData) return;
    const f = currentAuditData.findings.find(x => x.rule_id === ruleId);
    if (!f) return;

    modalRuleId.textContent = f.rule_id;
    modalCmd.textContent = f.command;
    modalVerdict.textContent = f.status;
    modalRawOutput.textContent = `Verdict: ${f.status}\nEvidence: ${f.evidence}`;
    
    evidenceModal.classList.remove('hidden');
  };

  // Copy Command Helper
  window.copyCommand = function(cmd, btn) {
    navigator.clipboard.writeText(cmd).then(() => {
      const orig = btn.textContent;
      btn.textContent = '✓ Copied!';
      btn.style.background = '#10b981';
      btn.style.color = '#000';
      setTimeout(() => {
        btn.textContent = orig;
        btn.style.background = '';
        btn.style.color = '';
      }, 2000);
    });
  };

  // Chatbot UI Helpers
  function appendUserMessage(msg) {
    const div = document.createElement('div');
    div.className = 'chat-bubble user';
    div.innerHTML = `<div class="bubble-content">${escapeHtml(msg)}</div>`;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function appendBotMessage(msg) {
    const div = document.createElement('div');
    div.className = 'chat-bubble bot';
    div.innerHTML = `<div class="bubble-content">${formatMarkdown(msg)}</div>`;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function setLoading(isLoading) {
    if (isLoading) {
      btnSpinner.classList.remove('hidden');
      btnIcon.classList.add('hidden');
      btnText.textContent = 'Auditing...';
      runAuditBtn.disabled = true;
    } else {
      btnSpinner.classList.add('hidden');
      btnIcon.classList.remove('hidden');
      btnText.textContent = 'Run Audit';
      runAuditBtn.disabled = false;
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function escapeJs(str) {
    if (!str) return '';
    return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  }

  function formatMarkdown(text) {
    if (!text) return '';
    let html = escapeHtml(text);
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    html = html.replace(/`(.*?)`/g, '<code>$1</code>');
    html = html.replace(/\n/g, '<br>');
    return html;
  }
});
