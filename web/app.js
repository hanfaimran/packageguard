    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    const VALID_TABS = ['scan', 'status', 'results', 'architecture'];

    function switchTab(tabId) {
      if (!VALID_TABS.includes(tabId)) {
        tabId = 'scan';
      }

      const buttons = document.querySelectorAll('.tab-btn');
      buttons.forEach(function(btn) {
        if (btn.getAttribute('data-tab') === tabId) {
          btn.classList.add('active');
        } else {
          btn.classList.remove('active');
        }
      });

      const panes = document.querySelectorAll('.tab-pane');
      panes.forEach(function(pane) {
        if (pane.id === 'tab-' + tabId) {
          pane.classList.add('active');
        } else {
          pane.classList.remove('active');
        }
      });

      if (window.location.hash !== '#' + tabId) {
        history.replaceState(null, '', '#' + tabId);
      }
    }

    function initTabFromHash() {
      const hash = window.location.hash.replace(/^#/, '');
      if (VALID_TABS.includes(hash)) {
        switchTab(hash);
      } else {
        switchTab('scan');
      }
    }

    window.addEventListener('hashchange', function() {
      const hash = window.location.hash.replace(/^#/, '');
      if (VALID_TABS.includes(hash)) {
        switchTab(hash);
      }
    });

    function checkConfig() {
      const banner = document.getElementById('configErrorBanner');
      if (window.__CONFIG_LOAD_FAILED || !window.PG_CONFIG || !window.PG_CONFIG.API_URL) {
        banner.style.display = 'block';
        return false;
      }
      banner.style.display = 'none';
      return true;
    }

    function fillAndScan(pkg, ver) {
      document.getElementById('pkgInput').value = pkg;
      document.getElementById('verInput').value = ver;
      triggerScan();
    }

    // Cached current report evidence for toggle
    let currentEvidenceList = [];
    let isShowingAllEvidence = false;

    async function triggerScan() {
      if (!checkConfig()) {
        const errDisp = document.getElementById('errorDisplay');
        errDisp.textContent = 'Cannot scan: config.js is missing or invalid. Please configure window.PG_CONFIG.';
        errDisp.style.display = 'block';
        return;
      }

      const pkgInput = document.getElementById('pkgInput');
      const verInput = document.getElementById('verInput');
      const scanBtn = document.getElementById('scanBtn');
      const errorDisplay = document.getElementById('errorDisplay');
      const statusMsg = document.getElementById('scanStatusMsg');
      const verdictCard = document.getElementById('verdictCard');
      const historyCard = document.getElementById('historyCard');

      const pkg = pkgInput.value.trim();
      const ver = verInput.value.trim();
      if (!pkg || !ver) return;

      errorDisplay.style.display = 'none';
      statusMsg.textContent = 'Scanning in progress... Please note: the first call may take up to 30 seconds due to Lambda cold start and registry tarball analysis.';
      statusMsg.style.display = 'block';
      scanBtn.disabled = true;
      scanBtn.textContent = 'Scanning...';

      const apiUrl = (window.PG_CONFIG.API_URL || '').replace(/\/$/, '');
      const apiKey = window.PG_CONFIG.API_KEY || '';

      try {
        const res = await fetch(apiUrl + '/scan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Api-Key': apiKey,
          },
          body: JSON.stringify({ package: pkg, version: ver })
        });

        const data = await res.json().catch(() => ({}));

        if (!res.ok) {
          throw new Error(data.error || ('Scan failed with HTTP ' + res.status));
        }

        const report = data.report || data;
        const scanId = data.scanId || report.scanId || '-';

        renderReport(report, scanId);
        verdictCard.style.display = 'block';
        verdictCard.scrollIntoView({ behavior: 'smooth' });

        // Trigger history fetch asynchronously
        fetchHistory(pkg, apiUrl, apiKey);
      } catch (err) {
        errorDisplay.textContent = err.message;
        errorDisplay.style.display = 'block';
      } finally {
        statusMsg.style.display = 'none';
        scanBtn.disabled = false;
        scanBtn.textContent = 'Scan Package';
      }
    }

    async function fetchHistory(pkg, apiUrl, apiKey) {
      const historyCard = document.getElementById('historyCard');
      const tbody = document.getElementById('historyTableBody');

      try {
        const res = await fetch(apiUrl + '/history?package=' + encodeURIComponent(pkg), {
          headers: {
            'X-Api-Key': apiKey,
          }
        });
        if (!res.ok) return;
        const data = await res.json();
        const scans = Array.isArray(data.scans) ? data.scans : [];

        if (scans.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No past scans recorded for this package.</td></tr>';
        } else {
          tbody.innerHTML = scans.map(function(s) {
            const verdict = escapeHtml(s.verdict || 'Review');
            const score = s.riskScore !== undefined ? s.riskScore : '--';
            const dateStr = s.scannedAt ? new Date(s.scannedAt).toLocaleString() : '-';

            return '<tr>' +
              '<td>' + escapeHtml(dateStr) + '</td>' +
              '<td><span class="code-inline">' + escapeHtml(s.scanId || '-') + '</span></td>' +
              '<td>' + escapeHtml(s.version || '-') + '</td>' +
              '<td><strong>' + escapeHtml(score) + '/100</strong></td>' +
              '<td><span class="badge-verdict ' + verdict.toLowerCase() + '" style="font-size: 0.75rem; padding: 0.2rem 0.6rem;">' + verdict + '</span></td>' +
              '<td>' + escapeHtml(s.verificationStatus || '-') + '</td>' +
            '</tr>';
          }).join('');
        }
        historyCard.style.display = 'block';
      } catch (err) {
        console.warn('History fetch failed:', err);
      }
    }

    function renderReport(report, scanId) {
      const badge = document.getElementById('verdictBadge');
      const verdict = report.verdict || 'Review';
      badge.textContent = verdict;
      badge.className = 'badge-verdict ' + verdict.toLowerCase();

      document.getElementById('reportTarget').textContent = (report.package || '') + '@' + (report.version || '');
      document.getElementById('reportScanId').textContent = 'Scan ID: ' + (scanId || '-');
      document.getElementById('reportVerification').textContent = 'Verification Status: ' + (report.verificationStatus || 'Unverified');

      document.getElementById('trustScoreVal').textContent = (report.riskScore !== undefined ? report.riskScore : '--') + '/100';
      
      currentEvidenceList = Array.isArray(report.evidence) ? report.evidence : [];
      document.getElementById('evidenceCountVal').textContent = currentEvidenceList.length;

      // Hard blocks
      const hardBlocksSec = document.getElementById('hardBlocksSection');
      const hardBlocksList = document.getElementById('hardBlocksList');
      if (Array.isArray(report.hardBlocks) && report.hardBlocks.length > 0) {
        hardBlocksList.innerHTML = report.hardBlocks
          .map(function(hb) { return '<li>' + escapeHtml(hb) + '</li>'; })
          .join('');
        hardBlocksSec.style.display = 'block';
      } else {
        hardBlocksSec.style.display = 'none';
        hardBlocksList.innerHTML = '';
      }

      // Evidence table & Show all toggle
      isShowingAllEvidence = false;
      renderEvidenceTable();

      // Remediation
      const remList = document.getElementById('remediationList');
      const remItems = Array.isArray(report.remediation) ? report.remediation : [];
      if (remItems.length === 0) {
        remList.innerHTML = '<li>No remediation needed. Package is considered healthy according to policy.</li>';
      } else {
        remList.innerHTML = remItems.map(function(r) {
          return '<li><strong>' + escapeHtml(r.issue) + ':</strong> ' + escapeHtml(r.recommendation) + '</li>';
        }).join('');
      }
    }

    function renderEvidenceTable() {
      const tbody = document.getElementById('evidenceTableBody');
      const toggleContainer = document.getElementById('evidenceToggleContainer');
      const toggleBtn = document.getElementById('evidenceToggleBtn');

      if (currentEvidenceList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No suspicious evidence or policy violations detected.</td></tr>';
        toggleContainer.style.display = 'none';
        return;
      }

      const displayItems = isShowingAllEvidence ? currentEvidenceList : currentEvidenceList.slice(0, 10);

      tbody.innerHTML = displayItems.map(function(ev) {
        let locText = '-';
        if (ev.location && ev.location.file) {
          locText = ev.location.file + (ev.location.line !== undefined ? (':' + ev.location.line) : '');
        }

        const sev = escapeHtml(ev.severity || 'INFO');
        const conf = (typeof ev.confidence === 'number') ? (ev.confidence * 100).toFixed(0) + '%' : '-';

        return '<tr>' +
          '<td><span class="code-inline">' + escapeHtml(ev.id) + '</span></td>' +
          '<td>' + escapeHtml(ev.category) + '</td>' +
          '<td><span class="severity-badge sev-' + sev + '">' + sev + '</span></td>' +
          '<td>' + escapeHtml(conf) + '</td>' +
          '<td>' + escapeHtml(ev.scanner) + '</td>' +
          '<td><span class="code-inline">' + escapeHtml(locText) + '</span></td>' +
          '<td>' + escapeHtml(ev.description) + (ev.snippet ? ('<pre style="margin-top:4px; font-size:0.75rem; background:var(--code-bg); padding:4px; border-radius:3px;">' + escapeHtml(ev.snippet) + '</pre>') : '') + '</td>' +
        '</tr>';
      }).join('');

      if (currentEvidenceList.length > 10) {
        toggleContainer.style.display = 'block';
        if (isShowingAllEvidence) {
          toggleBtn.textContent = 'Show less (first 10)';
        } else {
          toggleBtn.textContent = 'Show all (' + currentEvidenceList.length + ')';
        }
      } else {
        toggleContainer.style.display = 'none';
      }
    }

    function toggleAllEvidence() {
      isShowingAllEvidence = !isShowingAllEvidence;
      renderEvidenceTable();
    }

    document.addEventListener('DOMContentLoaded', function() {
      initTabFromHash();
      checkConfig();
    });
