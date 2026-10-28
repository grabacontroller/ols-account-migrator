/**
 * Account Migrator - UI.
 *
 * Plain ES2020, no build step and no dependencies, so the plugin stays a
 * single drop-in zip. All server calls go through api(), which attaches the
 * CSRF token and unwraps the JSON envelope.
 */

(function () {
  'use strict';

  var CFG = window.MIG || {};

  /**
   * The order steps are executed in. It must match the step ids the planner
   * emits and Engine::dispatch() understands; cron goes after email/ftp because
   * the endpoint authenticates as the freshly created account.
   */
  var order = [
    'package', 'account', 'domains', 'files', 'mail', 'fixperms',
    'databases', 'email', 'ftp', 'cron', 'suspend', 'ssl', 'verify'
  ];

  var state = {
    users: [],
    inventory: {},
    sourcePackages: {},
    plans: {},
    options: {},
    results: {},
    olsPackages: [],
    capabilities: null,
    resellers: null,
    reseller: (CFG.settings && CFG.settings.source && CFG.settings.source.reseller) || '',
    recreateReseller: false,
    resellerInfo: null,
    resellerOwnerKey: '',
    resellerResult: null,
    credText: '',
    activeTab: 'settings',
    pollTimer: null
  };

  /* ------------------------------------------------------------- utilities */

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function esc(v) {
    if (v === null || v === undefined) { return ''; }
    return String(v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function mb(v) {
    if (v === null || v === undefined || v === '' || v === 'unlimited') { return 'unlimited'; }
    var n = Number(v);
    if (isNaN(n)) { return String(v); }
    if (n >= 1048576) { return trim(n / 1048576) + ' TB'; }
    if (n >= 1024) { return trim(n / 1024) + ' GB'; }
    return n + ' MB';
  }

  function trim(n) {
    return String(Math.round(n * 100) / 100).replace(/\.0+$/, '').replace(/(\.\d*?)0+$/, '$1');
  }

  function bytes(n) {
    n = Number(n) || 0;
    if (n > 1073741824) { return trim(n / 1073741824) + ' GB'; }
    if (n > 1048576) { return trim(n / 1048576) + ' MB'; }
    if (n > 1024) { return trim(n / 1024) + ' KB'; }
    return n + ' B';
  }

  function toast(msg, kind) {
    var el = $('#toast');
    el.className = 'toast ' + (kind || '');
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(el._t);
    el._t = setTimeout(function () { el.hidden = true; }, kind === 'err' ? 9000 : 4200);
  }

  /** POST/GET wrapper around the plugin's JSON API.
   *
   * Sent as text/plain so the browser treats it as a "simple" request and skips
   * the CORS preflight: the panel's proxy answers OPTIONS without the
   * Access-Control-Allow-* headers, so a preflighted JSON POST fails with
   * "Failed to fetch". The server reads the raw body either way. */
  function api(action, payload) {
    var body = Object.assign({ action: action, _csrf: CFG.csrf }, payload || {});
    return fetch('index.php', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'text/plain;charset=UTF-8', 'Accept': 'application/json' },
      body: JSON.stringify(body)
    })
      .then(function (r) { return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }); })
      .then(function (j) {
        if (!j || j.ok !== true) { throw new Error((j && j.error) || 'Request failed'); }
        return j;
      });
  }

  function busy(btn, on, label) {
    if (!btn) { return; }
    btn.disabled = on;
    if (on) {
      btn.dataset.label = btn.textContent;
      btn.textContent = label || 'Working...';
    } else if (btn.dataset.label) {
      btn.textContent = btn.dataset.label;
    }
  }

  /* ------------------------------------------------------------------- tabs */

  function showTab(name) {
    state.activeTab = name;
    $$('.tab').forEach(function (t) { t.classList.toggle('active', t.dataset.tab === name); });
    $$('.panel').forEach(function (p) { p.classList.toggle('active', p.id === 'panel-' + name); });

    if (name === 'preflight' && !$('#panel-preflight').dataset.done) { runPreflight(); }
    if (name === 'report') { renderReport(); }
    if (name === 'updater') { loadUpdater(); }
  }

  $$('.tab').forEach(function (t) {
    t.addEventListener('click', function () { showTab(t.dataset.tab); });
  });

  /* --------------------------------------------------------------- settings */

  function field(label, name, value, opts) {
    opts = opts || {};
    var id = 'f_' + name.replace(/\./g, '_');
    var control;

    if (opts.type === 'select') {
      control = '<select id="' + id + '" data-name="' + esc(name) + '">' +
        (opts.options || []).map(function (o) {
          return '<option value="' + esc(o[0]) + '"' + (String(o[0]) === String(value) ? ' selected' : '') + '>' + esc(o[1]) + '</option>';
        }).join('') + '</select>';
    } else if (opts.type === 'checkbox') {
      return '<div class="check"><input type="checkbox" id="' + id + '" data-name="' + esc(name) + '"' +
        (value ? ' checked' : '') + '><label for="' + id + '">' + esc(label) +
        (opts.hint ? '<span class="hint" style="display:block">' + esc(opts.hint) + '</span>' : '') + '</label></div>';
    } else if (opts.type === 'password') {
      control = '<input type="password" id="' + id + '" data-name="' + esc(name) + '" value="' + esc(value) + '"' +
        ' placeholder="' + esc(value ? 'Unchanged - leave blank to keep' : 'not set') + '" autocomplete="new-password">';
    } else {
      control = '<input type="' + (opts.type || 'text') + '" id="' + id + '" data-name="' + esc(name) +
        '" value="' + esc(value) + '"' + (opts.placeholder ? ' placeholder="' + esc(opts.placeholder) + '"' : '') + '>';
    }

    return '<div><label for="' + id + '">' + esc(label) + '</label>' + control +
      (opts.hint ? '<div class="hint">' + esc(opts.hint) + '</div>' : '') + '</div>';
  }

  function collect(panel) {
    var out = {};
    $$('[data-name]', panel).forEach(function (el) {
      var k = el.dataset.name;
      if (el.type === 'checkbox') { out[k] = el.checked; }
      else { out[k] = el.value; }
    });
    return out;
  }

  function renderSettings(s) {
    var el = $('#panel-settings');
    el.innerHTML =
      '<h2>Connection settings</h2>' +
      '<p class="sub">Everything is stored encrypted on this server, in <span class="mono">data/config.json</span>. ' +
      'The migrator reuses your OLSpanel admin session by default, so the OLSpanel credentials below are usually not needed.</p>' +

      '<div class="card"><h3 style="margin-top:0">Source panel</h3><div class="grid two">' +
      field('Panel type', 'source.panel', s.source.panel, { type: 'select', options: [['directadmin', 'DirectAdmin'], ['cpanel', 'cPanel / WHM'], ['plesk', 'Plesk']] }) +
      field('Hostname or IP', 'source.host', s.source.host, { placeholder: 'old-server.example.com' }) +
      field('Port', 'source.port', s.source.port, { type: 'number', hint: 'DirectAdmin 2222, cPanel/WHM 2087, Plesk 8443' }) +
      field('Admin username', 'source.username', s.source.username, { hint: 'Plesk: root or administrator.' }) +
      (s.source.panel === 'cpanel'
        ? field('WHM API token', 'source.token', s.source.token, { type: 'password', hint: 'WHM &rarr; API Tokens. The root password also works.' })
        : s.source.panel === 'plesk'
          ? field('Plesk API key', 'source.token', s.source.token, { type: 'password', hint: 'Recommended. Tools &amp; Settings &rarr; Remote API (REST) &rarr; API keys.' }) +
            field('Administrator password (if no API key)', 'source.password', s.source.password, { type: 'password' })
          : field('Admin password', 'source.password', s.source.password, { type: 'password', hint: 'A DirectAdmin login key is recommended over the admin password.' })) +
      field('Restrict to reseller', 'source.reseller', s.source.reseller, { placeholder: 'optional', hint: 'DirectAdmin, cPanel or Plesk. Limits the scan to one reseller; you can also pick one in the Scan step.' }) +
      field('Verify TLS certificate', 'source.verify_tls', s.source.verify_tls, { type: 'checkbox', hint: 'Panels normally ship a self-signed certificate, so leave this off.' }) +
      '</div><div class="row tight" style="margin-top:14px">' +
      '<button class="btn ghost" id="btnTestSource">Test source connection</button>' +
      '<button class="btn ghost" id="btnTestOls">Test OLSpanel API</button>' +
      '<button class="btn" id="btnSaveSettings">Save settings</button>' +
      '</div><div id="settingsTestResult" style="margin-top:12px"></div></div>' +

      '<div class="card"><h3 style="margin-top:0">Files &amp; databases without SSH</h3>' +
      '<p class="hint" style="margin:-6px 0 12px">Optional. When SSH is disabled, files are copied over FTP/FTPS <em>or SFTP</em> with each ' +
      'account\'s own login, and databases are dumped over a direct MySQL connection with each account\'s own database ' +
      'credentials. The per-account passwords are pasted in the Select accounts step.</p><div class="grid two">' +
      field('Transfer protocol', 'source.ftp_protocol', s.source.ftp_protocol || 'ftp', { type: 'select', options: [['ftp', 'FTP / FTPS'], ['sftp', 'SFTP (over SSH)']] }) +
      field('Source FTP/SFTP port', 'source.ftp_port', s.source.ftp_port, { type: 'number', hint: 'FTP 21, SFTP 22 (or your host\'s SFTP port).' }) +
      field('FTP encryption', 'source.ftp_tls', s.source.ftp_tls, { type: 'select', options: [['auto', 'Opportunistic (FTPS if offered)'], ['force', 'Require FTPS'], ['off', 'Plain FTP']], hint: 'FTP/FTPS only; ignored for SFTP.' }) +
      field('FTP/SFTP login override', 'source.ftp_login', s.source.ftp_login, { placeholder: 'optional - defaults to the account name', hint: 'Use when the login is not the account name, e.g. an email SFTP user. {user}/{domain} are replaced.' }) +
      field('Source MySQL host', 'source.db_host', s.source.db_host, { placeholder: 'same as the panel host', hint: 'Must accept connections from this server.' }) +
      field('Source MySQL port', 'source.db_port', s.source.db_port, { type: 'number' }) +
      '</div></div>' +

      '<div class="card"><h3 style="margin-top:0">Source server SSH</h3>' +
      '<p class="hint" style="margin:-6px 0 12px">Required to copy files, mail and database contents. Use a dedicated key, not the root password.</p>' +
      '<div class="grid two">' +
      field('Enabled', 'ssh.enabled', s.ssh.enabled, { type: 'checkbox' }) +
      field('Hostname or IP', 'ssh.host', s.ssh.host) +
      field('Port', 'ssh.port', s.ssh.port, { type: 'number' }) +
      field('SSH user', 'ssh.username', s.ssh.username, { hint: 'root is needed for database dumps and cPanel metadata.' }) +
      field('Authentication', 'ssh.auth', s.ssh.auth, { type: 'select', options: [['key', 'SSH key'], ['password', 'Password (needs sshpass)']] }) +
      field('Private key path', 'ssh.key_path', s.ssh.key_path, { placeholder: '/root/.ssh/olsmig_ed25519' }) +
      field('SSH password', 'ssh.password', s.ssh.password, { type: 'password' }) +
      field('Strict host key checking', 'ssh.strict_host_key', s.ssh.strict_host_key, { type: 'checkbox' }) +
      '</div><div class="row tight" style="margin-top:14px">' +
      '<button class="btn ghost" id="btnTestSsh">Test SSH connection</button>' +
      '</div><div id="sshTestResult" style="margin-top:12px"></div></div>' +

      '<div class="card"><h3 style="margin-top:0">OLSpanel destination</h3>' +
      '<p class="hint" style="margin:-6px 0 12px">Leave the host blank to use the credentials forwarded by your panel session.</p>' +
      '<div class="grid two">' +
      field('Host (optional)', 'ols.host', s.ols.host, { placeholder: 'this-server.example.com' }) +
      field('Port (optional)', 'ols.port', s.ols.port, { type: 'number' }) +
      field('Admin username', 'ols.username', s.ols.username) +
      field('Admin password / token', 'ols.password', s.ols.password, { type: 'password' }) +
      field('API token', 'ols.token', s.ols.token, { type: 'password' }) +
      field('This server\'s public IP', 'server_ip', s.server_ip, { hint: 'Used to warn about DNS that still points elsewhere.' }) +
      '</div></div>' +

      '<div class="card"><h3 style="margin-top:0">Transfer behaviour</h3><div class="grid two">' +
      field('Home directory root', 'transfer.home_root', s.transfer.home_root) +
      field('Home directory template', 'transfer.user_home', s.transfer.user_home, { hint: 'Use %s for the username, e.g. /home/%s' }) +
      field('Bandwidth limit (KB/s)', 'transfer.bandwidth_limit', s.transfer.bandwidth_limit, { type: 'number', hint: '0 for unlimited' }) +
      field('Delete destination files not on source', 'transfer.delete_after', s.transfer.delete_after, { type: 'checkbox', hint: 'rsync --delete. Off by default for safety.' }) +
      field('Default PHP version', 'defaults.php_version', s.defaults.php_version, { placeholder: '8.2' }) +
      field('New package name template', 'defaults.new_package_naming', s.defaults.new_package_naming, { hint: '{source_package} and {username} are replaced.' }) +
      field('Generated password length', 'defaults.password_length', s.defaults.password_length, { type: 'number' }) +
      field('Auto-detect local MySQL', 'mysql.auto_detect', s.mysql.auto_detect, { type: 'checkbox', hint: 'Reads /root/.my.cnf and the OLSpanel config.' }) +
      field('MySQL host', 'mysql.host', s.mysql.host) +
      field('MySQL user', 'mysql.username', s.mysql.username) +
      field('MySQL root password', 'mysql.root_password', s.mysql.root_password, { type: 'password' }) +
      field('MySQL socket', 'mysql.socket', s.mysql.socket) +
      '</div><div class="notice" style="margin-top:14px">' +
      'Migrations are <strong>copy-only</strong>. Nothing on the source server is modified or deleted. ' +
      'Credentials for this panel are never written to the browser beyond a "set" marker.</div></div>' +

      '<div class="card"><h3 style="margin-top:0">Plugin updates</h3>' +
      '<p class="hint" style="margin:-6px 0 12px">The <strong>Plugin update</strong> tab checks this manifest and can ' +
      'install a newer bundle after verifying its checksum. It must be an HTTPS URL.</p><div class="grid two">' +
      field('Update manifest URL', 'updates.manifest_url', (s.updates || {}).manifest_url, { placeholder: 'https://dev3.vgs1st.com/account_migrator-version.json' }) +
      '</div></div>';

    $('#btnSaveSettings').addEventListener('click', function () {
      var btn = this;
      var payload = collect($('#panel-settings'));
      // Keep existing secrets when the field was left blank.
      ['source.password', 'source.token', 'ols.password', 'ols.token', 'ssh.password', 'mysql.root_password'].forEach(function (k) {
        var el = $('[data-name="' + k + '"]', $('#panel-settings'));
        if (el && el.value === '') { payload[k] = '__keep__'; }
      });
      busy(btn, true);
      api('settings_save', payload)
        .then(function () { toast('Settings saved.', 'ok'); return loadSettings(); })
        .catch(function (e) { toast(e.message, 'err'); })
        .finally(function () { busy(btn, false); });
    });

    $('#btnTestSource').addEventListener('click', function () {
      var btn = this;
      busy(btn, true);
      api('settings_save', collect($('#panel-settings')))
        .then(function () { return api('test_source'); })
        .then(function (j) {
          var r = j.result;
          $('#settingsTestResult').innerHTML = '<div class="notice ' + (r.ok ? 'good' : 'bad') + '">' + esc(r.message) + '</div>';
          toast(r.ok ? 'Source connection OK' : 'Source connection failed', r.ok ? 'ok' : 'err');
        })
        .catch(function (e) { toast(e.message, 'err'); })
        .finally(function () { busy(btn, false); });
    });

    $('#btnTestOls').addEventListener('click', function () {
      var btn = this;
      busy(btn, true);
      api('test_ols')
        .then(function (j) {
          state.olsPackages = j.packages || [];
          $('#settingsTestResult').innerHTML = '<div class="notice good">' + esc(j.message) + '</div>';
          toast('OLSpanel API OK', 'ok');
        })
        .catch(function (e) { toast(e.message, 'err'); })
        .finally(function () { busy(btn, false); });
    });

    $('#btnTestSsh').addEventListener('click', function () {
      var btn = this;
      busy(btn, true);
      api('settings_save', collect($('#panel-settings')))
        .then(function () { return api('test_ssh'); })
        .then(function (j) {
          var r = j.result;
          var tools = j.tools || {};
          var missing = Object.keys(tools).filter(function (k) { return !tools[k]; });
          var html = '<div class="notice ' + (r.ok ? 'good' : 'bad') + '">' + esc(r.message) + '</div>';
          if (missing.length) {
            html += '<div class="notice warn">Missing local tools: ' + esc(missing.join(', ')) +
              '. File and database transfers need these on the OLSpanel server.</div>';
          }
          $('#sshTestResult').innerHTML = html;
        })
        .catch(function (e) { toast(e.message, 'err'); })
        .finally(function () { busy(btn, false); });
    });

    // Keep the port/username sensible when the panel type changes.
    var panelSel = $('[data-name="source.panel"]', $('#panel-settings'));
    if (panelSel) {
      panelSel.addEventListener('change', function () {
        var port = $('[data-name="source.port"]', $('#panel-settings'));
        var user = $('[data-name="source.username"]', $('#panel-settings'));
        if (this.value === 'plesk') {
          if (port && (port.value === '' || port.value === '2222' || port.value === '2087')) { port.value = '8443'; }
          if (user && user.value === '') { user.value = 'root'; }
        } else if (this.value === 'cpanel') {
          if (port && port.value === '8443') { port.value = '2087'; }
        } else if (this.value === 'directadmin') {
          if (port && port.value === '8443') { port.value = '2222'; }
        }
      });
    }
  }

  function loadSettings() {
    return api('settings_get').then(function (j) {
      renderSettings(j.settings);
      // Keep the reseller picker in step with the saved settings.
      state.resellers = null;
      state.reseller = (j.settings.source && j.settings.source.reseller) || '';
      $('#identityChip').textContent = 'Signed in as ' + j.identity.user;
      $('#serverChip').textContent = j.server_ip ? 'This server: ' + j.server_ip : 'Server IP not set';
    });
  }

  /* -------------------------------------------------------------- preflight */

  function runPreflight() {
    var el = $('#panel-preflight');
    el.innerHTML = '<div class="loading">Checking the environment...</div>';
    api('preflight')
      .then(function (j) {
        el.dataset.done = '1';
        el.innerHTML = '<h2>Preflight checks</h2>' +
          '<p class="sub">Everything the migrator needs before it starts creating accounts.</p>' +
          '<div class="card">' + j.checks.map(function (c) {
            var cls = c.severity === 'info' ? 'info' : (c.ok ? 'ok' : 'bad');
            return '<details class="acc"><summary><span class="badge ' + cls + '">' + (c.ok ? 'OK' : (c.severity === 'info' ? 'INFO' : 'FIX')) +
              '</span><span>' + esc(c.name) + '</span></summary><div>' + esc(c.detail) + '</div></details>';
          }).join('') + '</div>' +
          '<button class="btn ghost" id="btnRerunPreflight">Re-run checks</button>';
        $('#btnRerunPreflight').addEventListener('click', function () { delete el.dataset.done; runPreflight(); });
      })
      .catch(function (e) { el.innerHTML = '<div class="notice bad">' + esc(e.message) + '</div>'; });
  }

  /* ------------------------------------------------------------------ scan */

  function sourceIsDirectAdmin() {
    return !!(CFG.settings && CFG.settings.source && CFG.settings.source.panel === 'directadmin');
  }

  function sourceSupportsResellers() {
    var p = CFG.settings && CFG.settings.source && CFG.settings.source.panel;
    return p === 'directadmin' || p === 'plesk';
  }

  function panelLabel() {
    var p = CFG.settings && CFG.settings.source && CFG.settings.source.panel;
    return p === 'plesk' ? 'Plesk' : 'DirectAdmin';
  }

  /** Fetch the reseller list once, then continue. */
  function ensureResellers(cb) {
    if (state.resellers !== null) { cb(); return; }
    api('resellers')
      .then(function (j) { state.resellers = j.resellers || []; })
      .catch(function () { state.resellers = []; })
      .then(function () { cb(); });
  }

  function resellerPicker() {
    var opts = ['<option value="">All accounts</option>'].concat(
      (state.resellers || []).map(function (r) {
        return '<option value="' + esc(r) + '"' + (String(r) === String(state.reseller) ? ' selected' : '') + '>' + esc(r) + '</option>';
      })
    ).join('');
    return '<div class="card" style="margin-bottom:14px"><h3 style="margin-top:0">' + esc(panelLabel()) + ' reseller</h3>' +
      '<p class="hint" style="margin:-6px 0 10px">Pick a reseller to migrate <strong>every hosting account it owns</strong> in one run.</p>' +
      '<select id="resellerPick">' + opts + '</select>' +
      '<div class="check" style="margin-top:12px"><input type="checkbox" id="recreateReseller"' + (state.recreateReseller ? ' checked' : '') + '>' +
      '<label for="recreateReseller">Recreate the reseller in OLSpanel <span class="hint" style="display:block">' +
      'Migrates the reseller\'s own account too and attaches its customers under it using the ' +
      '<strong>Reseller Manager</strong> plugin. Requires that plugin on this server.</span></label></div>' +
      '<div id="resellerInfoBox"></div></div>';
  }

  function renderScan() {
    var el = $('#panel-scan');
    var supportsResellers = sourceSupportsResellers();

    if (supportsResellers && state.resellers === null) {
      el.innerHTML = '<div class="loading">Loading resellers...</div>';
      ensureResellers(function () { renderScan(); });
      return;
    }

    if (!state.users.length) {
      el.innerHTML = '<h2>Select accounts</h2>' +
        '<p class="sub">Reads the list of accounts from the source panel. Nothing is changed.</p>' +
        (supportsResellers ? resellerPicker() : '') +
        '<button class="btn" id="btnScan">' + (state.reseller ? 'Scan reseller ' + esc(state.reseller) : 'Scan source panel') + '</button>' +
        '<div id="scanResult" style="margin-top:16px"></div>';
      var pick = $('#resellerPick');
      if (pick) {
        pick.addEventListener('change', function () { state.reseller = this.value; state.resellerInfo = null; state.recreateReseller = false; renderScan(); });
      }
      var recreate = $('#recreateReseller');
      if (recreate) {
        recreate.addEventListener('change', function () { state.recreateReseller = this.checked; state.resellerInfo = null; });
      }
      $('#btnScan').addEventListener('click', function () { doScan(this); });
      return;
    }

    var selected = Object.keys(state.options).filter(function (u) { return state.options[u] && state.options[u].selected; });

    el.innerHTML = '<h2>Select accounts</h2>' +
      '<p class="sub"><strong>' + state.users.length + '</strong> account(s)' +
      (state.reseller ? ' owned by reseller <strong>' + esc(state.reseller) + '</strong>' : '') +
      ' found on ' + esc(state.panel || 'the source') +
      '. Tick the ones to migrate, then load the plan.</p>' +
      '<div class="row tight"><button class="btn ghost" id="btnSelectAll">Select all</button>' +
      '<button class="btn ghost" id="btnSelectNone">Clear</button>' +
      '<button class="btn ghost" id="btnRescan">Rescan</button>' +
      '<span class="spacer"></span><button class="btn" id="btnLoadPlan" disabled>Load plan for ' + selected.length + ' account(s)</button></div>' +
      '<div class="tablewrap" style="margin-top:14px"><table><thead><tr>' +
      '<th style="width:38px"></th><th>Source user</th><th>Main domain</th><th class="num">Disk used</th>' +
      '<th class="num">Domains</th><th class="num">Email</th><th class="num">DBs</th><th>State</th>' +
      '</tr></thead><tbody>' +
      state.users.map(function (u) {
        var inv = state.inventory[u];
        var sel = state.options[u] && state.options[u].selected;
        var detail = inv && inv.error
          ? '<span class="badge failed">error</span> ' + esc(inv.error)
          : '<td>' + (inv ? esc(inv.domain) : '<span class="badge pending">not loaded</span>') + '</td>';
        return '<tr><td><input type="checkbox" data-user="' + esc(u) + '"' + (sel ? ' checked' : '') + '></td>' +
          '<td class="mono">' + esc(u) +
            (state.options[u] && state.options[u].is_reseller_owner ? ' <span class="badge info">reseller</span>' : '') + '</td>' +
          (inv && inv.error ? '<td colspan="5" style="color:#ff8f97">' + esc(inv.error) + '</td>'
            : '<td>' + (inv ? esc(inv.domain) : '<span class="badge pending">not loaded</span>') + '</td>' +
              '<td class="num">' + (inv ? esc(mb(inv.usage.disk_mb)) : '-') + '</td>' +
              '<td class="num">' + (inv ? (inv.domains || []).length : '-') + '</td>' +
              '<td class="num">' + (inv ? (inv.emails || []).length : '-') + '</td>' +
              '<td class="num">' + (inv ? (inv.databases || []).length : '-') + '</td>' +
              '<td>' + (inv && inv.suspended ? '<span class="badge warn">suspended</span>' : '<span class="badge ok">active</span>') + '</td>');
      }).join('') + '</tbody></table></div>' +
      '<div class="card" style="margin-top:16px"><h3 style="margin-top:0">Source credentials (only needed without SSH)</h3>' +
      '<p class="hint" style="margin:-6px 0 10px">Paste one line per account to copy files over FTP/SFTP and databases over a direct ' +
      'MySQL connection: <span class="mono">source_user:ftp_password:db_user:db_password</span>. Trailing fields may be ' +
      'omitted, blank lines and <span class="mono">#</span> comments are ignored. If SSH is enabled it takes precedence.</p>' +
      '<textarea id="credText" rows="5" style="width:100%" spellcheck="false" placeholder="alice:ftpPass:alice_wp:dbPass&#10;bob:ftpPass"></textarea>' +
      '</div>' +
      '<div id="scanStatus"></div>';

    $$('#panel-scan input[data-user]').forEach(function (cb) {
      cb.addEventListener('change', function () {
        var u = cb.dataset.user;
        state.options[u] = state.options[u] || {};
        state.options[u].selected = cb.checked;
        refreshScanButton();
      });
    });

    $('#btnSelectAll').addEventListener('click', function () {
      state.users.forEach(function (u) { state.options[u] = Object.assign({}, state.options[u], { selected: true }); });
      renderScan();
    });
    $('#btnSelectNone').addEventListener('click', function () {
      state.users.forEach(function (u) { state.options[u] = Object.assign({}, state.options[u], { selected: false }); });
      renderScan();
    });
    $('#btnRescan').addEventListener('click', function () { state.users = []; renderScan(); });
    $('#btnLoadPlan').addEventListener('click', loadPlan);
    var cred = $('#credText');
    if (cred) {
      cred.value = state.credText || '';
      cred.addEventListener('input', function () { state.credText = this.value; });
    }
    refreshScanButton();
  }

  function refreshScanButton() {
    var n = Object.keys(state.options).filter(function (u) { return state.options[u].selected; }).length;
    var btn = $('#btnLoadPlan');
    if (btn) { btn.textContent = 'Load plan for ' + n + ' account(s)'; btn.disabled = n === 0; }
  }

  function doScan(btn) {
    busy(btn, true, 'Scanning...');
    api('scan', { reseller: state.reseller || '' })
      .then(function (j) {
        state.users = j.users;
        state.panel = j.panel;
        state.capabilities = j.capabilities;
        if (j.reseller !== undefined) { state.reseller = j.reseller || ''; }
        state.inventory = {};
        state.options = {};
        state.users.forEach(function (u) { state.options[u] = { selected: true }; });
        toast('Found ' + j.users.length + ' account(s)' + (state.reseller ? ' for reseller ' + state.reseller : '') + '.', 'ok');
        if (state.recreateReseller && state.reseller) {
          return loadResellerInfo().then(function () { renderScan(); });
        }
        renderScan();
      })
      .catch(function (e) { toast(e.message, 'err'); })
      .finally(function () { busy(btn, false); });
  }

  /** Load the reseller's own account so it can be recreated after the run. */
  function loadResellerInfo() {
    return api('reseller_info', { reseller: state.reseller })
      .then(function (j) {
        state.resellerInfo = j;
        var ownerKey = (j.account && j.account.username) ? j.account.username : state.reseller;
        state.resellerOwnerKey = ownerKey;
        if (state.users.indexOf(ownerKey) < 0) {
          state.users.unshift(ownerKey);
          state.options[ownerKey] = { selected: true };
        }
        state.options[ownerKey] = Object.assign({}, state.options[ownerKey], { selected: true, is_reseller_owner: true });
        var alloc = (j.reseller && j.reseller.allocation) || {};
        $('#resellerInfoBox').innerHTML = '<div class="notice ' + (j.reseller_manager ? 'good' : 'warn') + '" style="margin-top:12px">' +
          (j.reseller_manager
            ? 'Reseller Manager detected. The reseller account <strong>' + esc(j.reseller.login || j.reseller.name) + '</strong> and ' +
              (j.reseller.users || []).length + ' customer account(s) will be attached after the migration.'
            : esc(j.note || 'Reseller Manager plugin not detected.')) + '</div>';
        if (!j.reseller_manager) {
          toast('Reseller Manager plugin not detected - the reseller cannot be recreated.', 'err');
        }
      })
      .catch(function (e) { toast('Reseller info: ' + e.message, 'err'); });
  }

  function loadPlan(btn) {
    var users = Object.keys(state.options).filter(function (u) { return state.options[u].selected; });
    busy(btn, true, 'Loading inventory...');
    var sshOn = !!(CFG.settings && CFG.settings.ssh && CFG.settings.ssh.enabled);

    api('credentials', { text: state.credText || '' })
      .then(function (j) {
        var creds = (j && j.credentials) || {};
        var defs = (CFG.settings && CFG.settings.defaults) || {};
        users.forEach(function (u) {
          var o = state.options[u] || (state.options[u] = {});
          if (creds[u]) {
            o.source_ftp_password = creds[u].ftp_password || '';
            o.source_db_user = creds[u].db_user || '';
            o.source_db_password = creds[u].db_password || '';
          }
          if (o.ssh_enabled === undefined) { o.ssh_enabled = sshOn; }
          if (o.include_files === undefined) {
            o.include_files = sshOn || !!o.source_ftp_password;
          }
          // Seed the resource toggles from the saved defaults so the ticked
          // boxes match the plan the server builds.
          if (o.include_databases === undefined) { o.include_databases = defs.generate_databases !== false; }
          if (o.import_database_data === undefined) { o.import_database_data = defs.import_database_data !== false; }
          if (o.include_email === undefined) { o.include_email = !!defs.create_email_accounts; }
          if (o.include_ftp === undefined) { o.include_ftp = false; }
          if (o.issue_ssl === undefined) { o.issue_ssl = !!defs.issue_ssl; }
        });
        return api('inventory', { users: users, options: state.options });
      })
      .then(function (j) {
        state.inventory = j.inventory || {};
        state.sourcePackages = j.source_packages || {};
        return api('plan', { inventory: state.inventory, options: state.options, source_packages: state.sourcePackages });
      })
      .then(function (j) {
        state.plans = j.plans || {};
        state.olsPackages = j.ols_packages || [];
        state.summary = j.summary;
        toast('Plan ready. Review it before running.', 'ok');
        showTab('plan');
        renderPlan();
      })
      .catch(function (e) { toast(e.message, 'err'); })
      .finally(function () { busy(btn, false); });
  }

  /* ------------------------------------------------------------------ plan */

  function renderPlan() {
    var el = $('#panel-plan');
    var plans = state.plans;
    var keys = Object.keys(plans);
    if (!keys.length) { el.innerHTML = '<div class="empty">No plan yet. Scan and select accounts first.</div>'; return; }

    var sum = state.summary || {};
    var selected = keys.filter(function (k) { return plans[k].selected; });

    el.innerHTML = '<h2>Review plan</h2>' +
      '<p class="sub">Nothing has been created yet. Adjust the per-account options below, then run.</p>' +
      '<div class="stats" style="margin-bottom:18px">' +
      stat(selected.length, 'Accounts') +
      stat(sum.domains || 0, 'Domains') +
      stat(sum.databases || 0, 'Databases') +
      stat(sum.emails || 0, 'Mailboxes') +
      stat(mb(sum.disk_mb || 0), 'Disk used') +
      stat(sum.warnings || 0, 'Warnings') +
      stat(sum.blocked || 0, 'Blocked') +
      '</div>' +
      '<div class="row tight"><button class="btn ghost" id="btnBackToScan">Back to selection</button>' +
      '<span class="spacer"></span><button class="btn good" id="btnGoRun" disabled>Run migration</button></div>' +
      '<div style="margin-top:16px">' + selected.map(planCard).join('') + '</div>';

    $('#btnBackToScan').addEventListener('click', function () { showTab('scan'); });
    $('#btnGoRun').addEventListener('click', function () { beginRun(); });

    var allClean = selected.every(function (k) { return !plans[k].blockers.length; });
    $('#btnGoRun').disabled = selected.length === 0 || !allClean;
    if (!allClean) {
      $('#btnGoRun').title = 'Some accounts have blockers - clear them first.';
    }

    $$('[data-opt]', el).forEach(function (input) {
      input.addEventListener('change', function () {
        var user = input.dataset.user;
        var key = input.dataset.opt;
        state.options[user] = state.options[user] || {};
        state.options[user][key] = input.type === 'checkbox' ? input.checked : input.value;
        // Re-plan just this account so the review stays truthful.
        api('plan', {
          inventory: { [user]: state.inventory[user] },
          options: { [user]: state.options[user] },
          source_packages: state.sourcePackages
        }).then(function (j) {
          state.plans[user] = j.plans[user];
          renderPlan();
        }).catch(function (e) { toast(e.message, 'err'); });
      });
    });
  }

  function stat(n, k) {
    return '<div class="stat"><div class="n">' + esc(n) + '</div><div class="k">' + esc(k) + '</div></div>';
  }

  function planCard(user) {
    var p = state.plans[user];
    var opts = state.options[user] || {};
    var inv = state.inventory[user] || {};

    var pkgSelect = '<select data-opt="pkg_id" data-user="' + esc(user) + '">' +
      '<option value="0">Auto (' + esc(p.package.action === 'create' ? 'create "' + p.package.name + '"' : 'use "' + p.package.name + '"') + ')</option>' +
      (state.olsPackages || []).map(function (pk) {
        var sel = String(opts.pkg_id || 0) === String(pk.id) ? ' selected' : '';
        return '<option value="' + esc(pk.id) + '"' + sel + '>' + esc(pk.name) + '</option>';
      }).join('') + '</select>';

    var blockers = p.blockers.map(function (b) { return '<div class="notice bad">' + esc(b) + '</div>'; }).join('');
    var warnings = p.warnings.map(function (w) { return '<div class="notice warn">' + esc(w) + '</div>'; }).join('');
    var notes = (p.inventory.notes || []).map(function (n) { return '<li>' + esc(n) + '</li>'; }).join('');

    var steps = p.steps.map(function (s) {
      return '<li><span class="badge ' + esc(s.status) + '">' + esc(s.status) + '</span>' +
        '<span class="step-title">' + esc(s.title) + '</span>' +
        '<span class="step-detail">' + esc(s.detail) + '</span></li>';
    }).join('');

    return '<details class="acc"' + (p.blockers.length ? ' open' : '') + '>' +
      '<summary><span class="badge ' + (p.blockers.length ? 'failed' : (p.suspended ? 'warn' : 'ok')) + '">' +
      esc(user) + '</span>' +
      '<span>' + esc(user) + ' &rarr; ' + esc(p.target_user) + ' (' + esc(p.main_domain) + ')</span>' +
      '<span class="spacer"></span>' +
      '<span class="badge info">' + esc(mb(p.inventory.usage.disk_mb)) + ' used</span></summary>' +

      '<div class="grid two">' +
      '<div><label>OLSpanel package</label>' + pkgSelect + '</div>' +
      '<div><label>OLSpanel username</label>' +
      '<input type="text" data-opt="target_user" data-user="' + esc(user) + '" value="' + esc(p.target_user) + '"></div>' +
      '</div>' +

      '<div style="margin-top:12px">' +
      optCheck('include_files', 'Copy files and mail (needs SSH)', !!opts.include_files, user) +
      optCheck('include_databases', 'Create databases', opts.include_databases !== false, user) +
      optCheck('import_database_data', 'Import database contents', opts.import_database_data !== false, user) +
      optCheck('include_email', 'Create email accounts', !!opts.include_email, user) +
      optCheck('include_ftp', 'Create FTP accounts', !!opts.include_ftp, user) +
      optCheck('issue_ssl', 'Issue SSL certificates (after DNS switch)', !!opts.issue_ssl, user) +
      '</div>' +

      '<h3>Resources</h3><div class="tablewrap"><table><tbody>' +
      '<tr><th>Domains</th><td>' + (Object.keys(p.domains).map(esc).join(', ') || '<span class="badge skipped">none</span>') + '</td></tr>' +
      '<tr><th>Subdomains</th><td>' + ((inv.subdomains || []).length + ' found (not separate vhosts on OLSpanel)') + '</td></tr>' +
      '<tr><th>Mailboxes</th><td>' + (Object.keys(p.emails).length ? Object.keys(p.emails).map(esc).join(', ') : '<span class="badge skipped">none</span>') + '</td></tr>' +
      '<tr><th>Databases</th><td>' + (Object.keys(p.databases).length ? Object.keys(p.databases).map(esc).join(', ') : '<span class="badge skipped">none</span>') + '</td></tr>' +
      '<tr><th>Source limits</th><td>' + limitLine(p.inventory.limits) + '</td></tr>' +
      '</tbody></table></div>' +

      '<h3>Steps</h3><ul class="steps">' + steps + '</ul>' +

      blockers + warnings +
      (notes ? '<h3>Source notes</h3><ul class="tight">' + notes + '</ul>' : '') +
      '</details>';
  }

  function optCheck(key, label, checked, user) {
    return '<div class="check"><input type="checkbox" data-opt="' + esc(key) + '" data-user="' + esc(user) + '"' +
      (checked ? ' checked' : '') + '><label>' + esc(label) + '</label></div>';
  }

  function limitLine(l) {
    if (!l) { return '-'; }
    return Object.keys(l).map(function (k) {
      var v = l[k];
      var text = (v === null || v === 0) ? 'unlimited' : (k.indexOf('mb') >= 0 ? mb(v) : String(v));
      return esc(k) + ': ' + esc(text);
    }).join(' &middot; ');
  }

  /* ------------------------------------------------------------------- run */

  function beginRun() {
    state.results = {};
    var users = Object.keys(state.plans).filter(function (k) { return state.plans[k].selected; });

    // One generated password per account, created client-side so it never
    // crosses the wire twice and is only shown to this admin.
    users.forEach(function (u) {
      state.options[u] = state.options[u] || {};
      state.options[u].generated_password = genPassword(Number(CFG.settings.defaults.password_length) || 14);
      state.options[u].db_password = genPassword(16);
      state.options[u].php_version = state.options[u].php_version || CFG.settings.defaults.php_version;
    });

    if (!confirm(
      'Create ' + users.length + ' account(s) on OLSpanel and transfer their files?\n\n' +
      'This only copies data - the source server is not modified.'
    )) { return; }

    showTab('run');
    renderRun();
    runNext(users, 0);
  }

  function genPassword(len) {
    var sets = [
      'abcdefghijkmnopqrstuvwxyz',
      'ABCDEFGHJKLMNPQRSTUVWXYZ',
      '23456789',
      '!@#$%^&*-_=+?'
    ];
    var all = sets.join('');
    var out = sets.map(function (s) { return s[Math.floor(Math.random() * s.length)]; }).join('');
    while (out.length < len) { out += all[Math.floor(Math.random() * all.length)]; }
    return out.split('').sort(function () { return Math.random() - 0.5; }).join('');
  }

  function renderRun() {
    var el = $('#panel-run');
    var users = Object.keys(state.results);
    if (!users.length) { el.innerHTML = '<div class="loading">Starting migration...</div>'; return; }

    var done = 0, total = 0;
    Object.keys(state.results).forEach(function (u) {
      Object.keys(state.results[u]).forEach(function (s) {
        total++;
        if (['done', 'skipped'].indexOf(state.results[u][s].status) >= 0) { done++; }
      });
    });

    el.innerHTML = '<h2>Migration</h2>' +
      '<p class="sub">Large transfers run in the background and keep going even if you close this page.</p>' +
      '<div class="progress" style="margin-bottom:18px"><span style="width:' + (total ? Math.round(done / total * 100) : 0) + '%"></span></div>' +
      Object.keys(state.results).map(function (u) {
        var rows = Object.keys(state.results[u]).map(function (s) {
          var r = state.results[u][s];
          return '<li><span class="badge ' + esc(r.status) + '">' + esc(r.status) + '</span>' +
            '<span class="step-title">' + esc(s) + '</span>' +
            '<span class="step-detail">' + esc(r.message) + '</span></li>';
        }).join('');
        return '<details class="acc" open><summary><span class="badge ' + (accountDone(u) ? 'ok' : 'running') + '">' +
          esc(u) + '</span><span>' + esc(state.plans[u].target_user) + '</span></summary>' +
          '<ul class="steps">' + rows + '</ul></details>';
      }).join('') +
      '<h3>Live log</h3><pre class="log" id="runLog"></pre>' +
      '<div class="row tight"><button class="btn ghost" id="btnRefreshReport">Open report</button></div>';

    $('#btnRefreshReport').addEventListener('click', function () { showTab('report'); });
    var log = $('#runLog');
    if (log && state.logText) { log.textContent = state.logText; log.scrollTop = log.scrollHeight; }
  }

  function accountDone(user) {
    var r = state.results[user];
    return Object.keys(r).every(function (s) {
      return ['done', 'skipped', 'blocked'].indexOf(r[s].status) >= 0;
    });
  }

  /** Execute the ordered step list for one account, one step at a time. */
  function runNext(users, index) {
    if (index >= users.length) {
      state.logText = state.logText || '';
      renderRun();
      toast('Migration finished. Review the report.', 'ok');
      if (state.recreateReseller && state.resellerInfo) {
        finalizeReseller().then(function () { showTab('report'); });
      } else {
        showTab('report');
      }
      return;
    }

    var user = users[index];
    var plan = state.plans[user];
    var opts = state.options[user] || {};
    state.results[user] = state.results[user] || {};

    // Only run the steps that are not already satisfied.
    var queue = order.filter(function (id) {
      if (state.results[user][id]) { return false; }
      var planned = plan.steps.some(function (s) { return s.id === id; });
      if (!planned) { return false; }
      if (id === 'account' || id === 'domains' || id === 'package') {
        return (state.results[user][id] || {}).status !== 'exists';
      }
      return true;
    });

    runStep(user, queue, 0);
  }

  function runStep(user, queue, qi) {
    if (qi >= queue.length) { runNext(Object.keys(state.plans).filter(function (k) { return state.plans[k].selected; }), nextUserIndex(user) + 1); return; }

    var stepId = queue[qi];
    var plan = state.plans[user];
    var opts = state.options[user] || {};
    state.results[user][stepId] = { status: 'running', message: 'Working...' };
    state.logText = (state.logText || '') + '[' + user + '] ' + stepId + '...\n';
    renderRun();

    api('run_step', { plan: plan, step: stepId, options: opts })
      .then(function (j) {
        var r = j.result;
        state.results[user][stepId] = r;
        state.logText += '  -> ' + r.status + ': ' + r.message + '\n';
        if (j.log) { state.logText += j.log; }

        if (r.status === 'running' && (stepId === 'files' || stepId === 'mail')) {
          pollTransfer(user, stepId);
          return;
        }
        if (r.status === 'running') { pollStep(user, queue, qi, stepId); return; }
        renderRun();
        runStep(user, queue, qi + 1);
      })
      .catch(function (e) {
        state.results[user][stepId] = { status: 'failed', message: e.message };
        state.logText += '  -> ERROR: ' + e.message + '\n';
        renderRun();
        runStep(user, queue, qi + 1);
      });
  }

  function nextUserIndex(user) {
    return Object.keys(state.plans).filter(function (k) { return state.plans[k].selected; }).indexOf(user);
  }

  function pollStep(user, queue, qi, stepId) {
    setTimeout(function () {
      api('run_step', { plan: state.plans[user], step: stepId, options: state.options[user] || {} })
        .then(function (j) {
          state.results[user][stepId] = j.result;
          renderRun();
          if (j.result.status === 'running') { pollStep(user, queue, qi, stepId); return; }
          runStep(user, queue, qi + 1);
        })
        .catch(function () { runStep(user, queue, qi + 1); });
    }, 2500);
  }

  /** Poll a detached rsync job until it exits. */
  function pollTransfer(user, stage) {
    var tries = 0;
    var timer = setInterval(function () {
      tries++;
      api('poll', { plan: state.plans[user], stage: stage })
        .then(function (j) {
          var r = j.result;
          state.results[user][stage] = r;
          if (r.extra && r.extra.log) {
            state.logText += r.extra.log + '\n';
          }
          renderRun();
          if (r.status === 'running' && tries < 2400) { return; }
          clearInterval(timer);
          runStep(user, rebuildQueue(user), rebuildQueue(user).indexOf(stage) + 1);
        })
        .catch(function () { clearInterval(timer); });
    }, 3000);
  }

  function rebuildQueue(user) {
    var plan = state.plans[user];
    return order.filter(function (id) { return plan.steps.some(function (s) { return s.id === id; }); });
  }

  /* ---------------------------------------------------------------- report */

  /** Recreate the reseller and attach its migrated customers. */
  function finalizeReseller() {
    var info = state.resellerInfo || {};
    var ownerKey = state.resellerOwnerKey;
    var ownerPlan = state.plans[ownerKey] || null;
    var target = ownerPlan ? ownerPlan.target_user : state.reseller;
    var infoReseller = info.reseller || {};

    var reseller = {
      username: target,
      email: (ownerPlan && ownerPlan.email) || infoReseller.email || '',
      domain: (ownerPlan && ownerPlan.main_domain) || (info.account && info.account.domain) || '',
      password: (state.options[ownerKey] && state.options[ownerKey].generated_password) || genPassword(14),
      php_version: (CFG.settings && CFG.settings.defaults && CFG.settings.defaults.php_version) || '8.2',
      unlimited_everything: false,
      allocation: infoReseller.allocation || {},
      package_name: 'reseller-' + target
    };

    var customers = [];
    Object.keys(state.plans).forEach(function (u) {
      if (u === ownerKey || !state.plans[u] || !state.plans[u].selected) { return; }
      var inv = state.inventory[u] || {};
      customers.push({
        username: state.plans[u].target_user,
        source_package: inv.package || '',
        limits: inv.limits || {},
        package_name: (state.plans[u].package && state.plans[u].package.name) || ''
      });
    });

    return api('attach_reseller', { reseller: reseller, customers: customers })
      .then(function (j) {
        state.resellerResult = j.result;
        state.logText += '\nReseller: ' + ((j.result && j.result.message) || '') + '\n';
        toast('Reseller recreated.', 'ok');
      })
      .catch(function (e) {
        state.resellerResult = { ok: false, message: e.message };
        state.logText += '\nReseller attach failed: ' + e.message + '\n';
        toast('Reseller attach failed: ' + e.message, 'err');
      });
  }

  function renderReport() {
    var el = $('#panel-report');
    if (!Object.keys(state.results).length) {
      el.innerHTML = '<div class="empty">Nothing has been migrated yet.</div>';
      return;
    }

    var issues = [];
    var creds = [];

    Object.keys(state.results).forEach(function (u) {
      Object.keys(state.results[u]).forEach(function (s) {
        var r = state.results[u][s];
        if (['failed', 'partial', 'blocked'].indexOf(r.status) >= 0) {
          issues.push({ user: u, step: s, status: r.status, message: r.message });
        }
        if (r.extra) {
          if (r.extra.password) { creds.push({ user: u, what: s + ' password', value: r.extra.password }); }
          if (r.extra.credentials) {
            Object.keys(r.extra.credentials).forEach(function (db) {
              if (r.extra.credentials[db].db_pass) {
                creds.push({ user: u, what: 'DB ' + db + ' (' + r.extra.credentials[db].db_user + ')', value: r.extra.credentials[db].db_pass });
              }
            });
          }
          if (r.extra.manual) {
            issues.push({ user: u, step: s, status: 'manual', message: 'Create these mailboxes by hand: ' + r.extra.manual.join(', ') });
          }
        }
      });
    });

    el.innerHTML = '<h2>Report</h2>' +
      '<p class="sub">Post-migration checklist and anything that still needs a human.</p>' +

      '<div class="card"><h3 style="margin-top:0">Manual follow-up' + (issues.length ? ' (' + issues.length + ')' : '') + '</h3>' +
      (issues.length
        ? issues.map(function (i) {
            return '<details class="acc"><summary><span class="badge ' + esc(i.status === 'manual' ? 'warn' : 'failed') + '">' +
              esc(i.status) + '</span><span>' + esc(i.user) + ' &rarr; ' + esc(i.step) + '</span></summary>' +
              '<div>' + esc(i.message) + '</div></details>';
          }).join('')
        : '<div class="notice good">Nothing failed. Every step completed or was intentionally skipped.</div>') +
      '</div>' +

      (state.resellerResult
        ? '<div class="card"><h3 style="margin-top:0">Reseller</h3>' +
          '<div class="notice ' + (state.resellerResult.ok === false ? 'bad' : 'good') + '">' +
          esc(state.resellerResult.message || '') + '</div>' +
          (state.resellerResult.password
            ? '<p>Reseller sign-in: <span class="mono">' + esc(state.resellerResult.reseller || '') + '</span> / ' +
              '<span class="mono">' + esc(state.resellerResult.password) + '</span></p>'
            : '') +
          '</div>'
        : '') +

      '<div class="card"><h3 style="margin-top:0">Generated credentials</h3>' +
      '<div class="notice warn">These were shown once and are not stored in plain text. Save them before closing this page.</div>' +
      (creds.length
        ? '<div class="tablewrap"><table><thead><tr><th>Account</th><th>Item</th><th>Value</th></tr></thead><tbody>' +
          creds.map(function (c) {
            return '<tr><td>' + esc(c.user) + '</td><td>' + esc(c.what) + '</td><td class="mono">' + esc(c.value) + '</td></tr>';
          }).join('') + '</tbody></table></div>'
        : '<p class="hint">No credentials were generated.</p>') +
      '</div>' +

      '<div class="card"><h3 style="margin-top:0">Cutover checklist</h3><ul class="tight">' +
      '<li>Update the A record of every migrated domain to ' + esc(CFG.serverIp || 'the OLSpanel server IP') + ' at your registrar.</li>' +
      '<li>Lower the DNS TTL to 300 <em>before</em> starting a migration so cutover is quick.</li>' +
      '<li>Once DNS has switched, issue the SSL certificates.</li>' +
      '<li>Test each site and mailbox, then lower the TTL back to your normal value.</li>' +
      '<li>Remove or disable the migrated accounts on the source panel <em>after</em> everything works.</li>' +
      '</ul></div>' +

      '<div class="card"><h3 style="margin-top:0">Migration log</h3>' +
      '<pre class="log" id="reportLog"></pre></div>';

    var log = $('#reportLog');
    if (log) { log.textContent = state.logText || ''; log.scrollTop = log.scrollHeight; }
  }

  /* -------------------------------------------------------------- updater */

  function loadUpdater() {
    var el = $('#panel-updater');
    el.innerHTML = '<div class="loading">Checking for updates&hellip;</div>';
    api('update_check')
      .then(function (j) { renderUpdater(j.update || {}); })
      .catch(function (e) { renderUpdaterError(e.message); });
  }

  function renderUpdater(info) {
    var available = !!info.available;
    $('#panel-updater').innerHTML = '<h2>Plugin update</h2>' +
      '<p class="sub">Check the published Account Migrator bundle and install a newer version on this server.</p>' +
      '<div class="card"><h3 style="margin-top:0">Version</h3>' +
      '<div class="tablewrap"><table><tbody>' +
      '<tr><th style="text-align:left">Installed</th><td class="mono">v' + esc(info.current || CFG.version || '?') + '</td></tr>' +
      '<tr><th style="text-align:left">Latest published</th><td class="mono">v' + esc(info.latest || 'unknown') + '</td></tr>' +
      '<tr><th style="text-align:left">Latest update</th><td class="mono">' + esc(info.updated || 'unknown') + '</td></tr>' +
      '<tr><th style="text-align:left">Manifest</th><td class="mono">' + esc(info.manifest_url || '') + '</td></tr>' +
      '</tbody></table></div>' +
      (info.notes ? '<p class="hint" style="margin-top:10px">' + esc(info.notes) + '</p>' : '') +
      '<div class="notice ' + (available ? 'warn' : 'good') + '" style="margin-top:14px">' +
      (available
        ? 'A newer version (v' + esc(info.latest) + ') is available.'
        : 'This plugin is up to date (v' + esc(info.current || CFG.version || '?') + ').') +
      '</div>' +
      '<div class="row tight" style="margin-top:14px">' +
      (available ? '<button class="btn" id="btnInstallUpdate">Install v' + esc(info.latest) + '</button>' : '') +
      '<button class="btn ghost" id="btnRecheck">Check again</button>' +
      '</div>' +
      '<div id="updateOutput"></div>' +
      '</div>';

    var recheck = $('#btnRecheck');
    if (recheck) { recheck.addEventListener('click', loadUpdater); }
    var install = $('#btnInstallUpdate');
    if (install) { install.addEventListener('click', function () { installUpdateNow(info.latest); }); }
  }

  function renderUpdaterError(message) {
    $('#panel-updater').innerHTML = '<h2>Plugin update</h2>' +
      '<p class="sub">Check the published Account Migrator bundle and install a newer version on this server.</p>' +
      '<div class="notice bad">Could not check for updates: ' + esc(message) + '</div>' +
      '<p class="hint">The manifest URL defaults to dev3.vgs1st.com. You can change it under Settings.</p>' +
      '<div class="row tight"><button class="btn ghost" id="btnRecheck2">Check again</button></div>';
    var r = $('#btnRecheck2');
    if (r) { r.addEventListener('click', loadUpdater); }
  }

  function installUpdateNow(version) {
    if (!confirm('Install v' + version + '?\n\nThe plugin will be refreshed. Settings are kept.')) { return; }
    var btn = $('#btnInstallUpdate');
    busy(btn, true, 'Installing...');
    api('update_install', { confirm: true })
      .then(function (j) {
        var r = j.result || {};
        toast(r.message || 'Update complete.', 'ok');
        var out = $('#updateOutput');
        if (out && r.output) {
          out.innerHTML = '<h3 style="margin:16px 0 8px">Installer output</h3>' +
            '<pre class="log">' + esc(r.output) + '</pre>' +
            '<div class="row tight" style="margin-top:12px"><button class="btn" id="btnReloadUpd">Reload</button></div>';
          var rb = $('#btnReloadUpd');
          if (rb) { rb.addEventListener('click', function () { location.reload(); }); }
        } else if (r.installed) {
          setTimeout(function () { location.reload(); }, 1800);
        }
      })
      .catch(function (e) { toast(e.message, 'err'); })
      .finally(function () { busy(btn, false); });
  }

  /* ------------------------------------------------------------------ boot */

  $('#identityChip').textContent = 'Signed in as ' + ((CFG.identity && CFG.identity.user) || 'admin');
  $('#serverChip').textContent = CFG.serverIp ? 'This server: ' + CFG.serverIp : 'Server IP not set';
  loadSettings().catch(function (e) { toast(e.message, 'err'); });
})();