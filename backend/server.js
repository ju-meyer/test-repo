const express = require('express');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'frontend')));

const SYSTEM_CONTAINERS = [
  'jellyfin',
  'jellyseerr',
  'radarr',
  'sonarr',
  'qbittorrent',
  'gluetun',
  'nginx'
];

const SAFE_READ_ONLY_COMMANDS = [
  'docker ps',
  'docker inspect',
  'docker logs',
  'systemctl status',
  'ip addr',
  'ip route',
  'ping'
];

const QBITTORRENT_URL = process.env.QBITTORRENT_URL || 'http://127.0.0.1:8080';
const QBITTORRENT_USERNAME = process.env.QBITTORRENT_USERNAME || '';
const QBITTORRENT_PASSWORD = process.env.QBITTORRENT_PASSWORD || '';

function runCommand(command, args = []) {
  return execFileAsync(command, args, { maxBuffer: 8 * 1024 * 1024 });
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getCpuTimes() {
  const cpus = os.cpus();
  return cpus.reduce(
    (acc, cpu) => {
      acc.idle += cpu.times.idle;
      acc.total += Object.values(cpu.times).reduce((sum, time) => sum + time, 0);
      return acc;
    },
    { idle: 0, total: 0 }
  );
}

async function getCpuUtilization() {
  const start = getCpuTimes();
  await wait(250);
  const end = getCpuTimes();
  const idleDelta = end.idle - start.idle;
  const totalDelta = end.total - start.total;
  if (totalDelta <= 0) return 0;
  return Number((((totalDelta - idleDelta) / totalDelta) * 100).toFixed(1));
}

function getMemoryUtilization() {
  const total = os.totalmem();
  const free = os.freemem();
  const used = total - free;
  return {
    totalBytes: total,
    usedBytes: used,
    freeBytes: free,
    utilizationPercent: Number(((used / total) * 100).toFixed(1))
  };
}



async function getQbittorrentTorrents() {
  const loginUrl = `${QBITTORRENT_URL}/api/v2/auth/login`;
  const torrentsUrl = `${QBITTORRENT_URL}/api/v2/torrents/info`;
  let sessionCookie = '';

  if (QBITTORRENT_USERNAME && QBITTORRENT_PASSWORD) {
    const body = new URLSearchParams({
      username: QBITTORRENT_USERNAME,
      password: QBITTORRENT_PASSWORD
    });

    const authResponse = await fetch(loginUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });

    if (!authResponse.ok) {
      throw new Error(`qBittorrent auth failed (HTTP ${authResponse.status}).`);
    }

    const setCookie = authResponse.headers.get('set-cookie') || '';
    sessionCookie = setCookie.split(';')[0];
  }

  const headers = {};
  if (sessionCookie) {
    headers.Cookie = sessionCookie;
  }

  const response = await fetch(torrentsUrl, { headers });
  if (!response.ok) {
    throw new Error(`qBittorrent torrents request failed (HTTP ${response.status}).`);
  }

  const payload = await response.json();
  return payload.map((torrent) => ({
    name: torrent.name,
    state: torrent.state,
    progressPercent: Number(((torrent.progress || 0) * 100).toFixed(1)),
    downloaded: torrent.downloaded,
    size: torrent.size,
    etaSeconds: torrent.eta,
    downloadSpeed: torrent.dlspeed,
    uploadSpeed: torrent.upspeed,
    category: torrent.category || 'uncategorized'
  }));
}

async function getStorageUtilization(mountPath = '/media') {
  try {
    const { stdout } = await runCommand('df', ['-P', mountPath]);
    const lines = stdout.trim().split('\n');
    if (lines.length < 2) {
      throw new Error('Unable to parse df output.');
    }

    const parts = lines[1].split(/\s+/);
    return {
      filesystem: parts[0],
      totalKB: Number(parts[1]),
      usedKB: Number(parts[2]),
      availableKB: Number(parts[3]),
      utilizationPercent: Number(parts[4].replace('%', '')),
      mountPath: parts[5]
    };
  } catch (error) {
    return {
      mountPath,
      error: `Could not read storage usage for ${mountPath}: ${error.message}`
    };
  }
}

async function getContainerList() {
  const format = '{{json .}}';
  const { stdout } = await runCommand('docker', ['ps', '-a', '--format', format]);
  const lines = stdout.split('\n').filter(Boolean);
  return lines.map((line) => {
    const parsed = JSON.parse(line);
    return {
      id: parsed.ID,
      image: parsed.Image,
      name: parsed.Names,
      status: parsed.Status,
      state: parsed.State
    };
  });
}

async function inspectContainer(containerName) {
  const { stdout } = await runCommand('docker', ['inspect', containerName]);
  const parsed = JSON.parse(stdout);
  return parsed[0];
}

async function getContainerLogs(containerName, tail = 400) {
  const { stdout, stderr } = await runCommand('docker', ['logs', '--tail', String(tail), containerName]);
  return `${stdout}\n${stderr}`.trim();
}

function parseLogs(rawLogs) {
  const lines = rawLogs.split('\n');
  const errors = [];
  const warnings = [];
  const stackTraces = [];

  let stackBuffer = [];

  for (const line of lines) {
    if (/\b(ERROR|Error|error|FATAL|fatal)\b/.test(line)) {
      errors.push(line);
    }

    if (/\b(WARN|Warning|warning)\b/.test(line)) {
      warnings.push(line);
    }

    if (/^\s+at\s+/.test(line) || /^Traceback/.test(line)) {
      stackBuffer.push(line);
    } else if (stackBuffer.length > 0) {
      stackTraces.push(stackBuffer.join('\n'));
      stackBuffer = [];
    }
  }

  if (stackBuffer.length > 0) {
    stackTraces.push(stackBuffer.join('\n'));
  }

  return {
    errorCount: errors.length,
    warningCount: warnings.length,
    stackTraceCount: stackTraces.length,
    topErrors: errors.slice(-10),
    topWarnings: warnings.slice(-10),
    stackTraces: stackTraces.slice(-5)
  };
}

function scoreContainerHealth(container, inspectData, logSummary) {
  const reasons = [];
  let score = 100;

  const healthStatus = inspectData?.State?.Health?.Status;
  const runningState = inspectData?.State?.Status;

  if (runningState !== 'running') {
    score -= 70;
    reasons.push(`Container is not running (state: ${runningState || 'unknown'}).`);
  }

  if (healthStatus === 'unhealthy') {
    score -= 40;
    reasons.push('Docker health check reports unhealthy status.');
  }

  if (logSummary.errorCount > 0) {
    score -= Math.min(30, logSummary.errorCount * 2);
    reasons.push(`Detected ${logSummary.errorCount} error log lines.`);
  }

  if (logSummary.warningCount > 5) {
    score -= Math.min(20, Math.floor(logSummary.warningCount / 2));
    reasons.push(`Detected elevated warning volume (${logSummary.warningCount} lines).`);
  }

  if (/restarting/i.test(container.status)) {
    score -= 50;
    reasons.push('Container appears to be restarting frequently.');
  }

  if (score < 0) score = 0;

  let level = 'Healthy';
  if (score < 40) {
    level = 'Critical';
  } else if (score < 75) {
    level = 'Warning';
  }

  return { level, score, reasons };
}

function detectCommonIssues(containerName, logs) {
  const findings = [];
  const lower = logs.toLowerCase();

  if (/(permission denied|eacces|operation not permitted)/i.test(logs)) {
    findings.push({
      type: 'permission',
      severity: 'Warning',
      message: `${containerName}: Permission-related failures detected in logs.`,
      safeFix: 'Verify UID/GID mappings and read/write permissions on mounted paths such as /media.'
    });
  }

  if (containerName.includes('gluetun') && /(vpn|tun|route).*(fail|error|down|timeout)/i.test(logs)) {
    findings.push({
      type: 'vpn-routing',
      severity: 'Critical',
      message: 'Gluetun logs indicate potential VPN routing or tunnel instability.',
      safeFix: 'Check VPN provider credentials, tunnel endpoint reachability, and confirm dependent containers use Gluetun network namespace.'
    });
  }

  if (/(network is unreachable|connection timed out|temporary failure in name resolution|no route to host)/i.test(logs)) {
    findings.push({
      type: 'network',
      severity: 'Warning',
      message: `${containerName}: Network connectivity errors detected.`,
      safeFix: 'Inspect DNS settings, bridge network health, and outbound connectivity via read-only network checks.'
    });
  }

  if (/(import failed|failed to import|path does not exist|no such file or directory)/i.test(lower) && containerName.includes('radarr')) {
    findings.push({
      type: 'radarr-import',
      severity: 'Warning',
      message: 'Radarr import failures detected in logs.',
      safeFix: 'Ensure completed download paths map consistently between qBittorrent and Radarr (/media mount mapping must match).' 
    });
  }

  return findings;
}

function mapQueryToDiagnostics(query) {
  const q = query.toLowerCase();

  if (q.includes('radarr') && q.includes('import')) {
    return { targetContainers: ['radarr', 'qbittorrent'], focus: 'import_pipeline' };
  }

  if (q.includes('vpn')) {
    return { targetContainers: ['gluetun'], focus: 'vpn_health' };
  }

  if (q.includes('restart') && q.includes('unhealthy')) {
    return { targetContainers: SYSTEM_CONTAINERS, focus: 'restart_unhealthy' };
  }

  if (q.includes('download') && q.includes('stalled')) {
    return { targetContainers: ['qbittorrent', 'gluetun', 'sonarr', 'radarr'], focus: 'download_stall' };
  }

  return { targetContainers: SYSTEM_CONTAINERS, focus: 'general' };
}

app.get('/api/containers', async (_req, res) => {
  try {
    const containers = await getContainerList();
    res.json({ containers });
  } catch (error) {
    res.status(500).json({ error: `Failed to list containers: ${error.message}` });
  }
});

app.get('/api/logs/:containerName', async (req, res) => {
  try {
    const logs = await getContainerLogs(req.params.containerName, Number(req.query.tail || 400));
    res.json({ container: req.params.containerName, logs });
  } catch (error) {
    res.status(500).json({ error: `Failed to read logs: ${error.message}` });
  }
});

app.get('/api/log-summary/:containerName', async (req, res) => {
  try {
    const logs = await getContainerLogs(req.params.containerName, Number(req.query.tail || 400));
    const summary = parseLogs(logs);
    const findings = detectCommonIssues(req.params.containerName, logs);
    res.json({ container: req.params.containerName, summary, findings });
  } catch (error) {
    res.status(500).json({ error: `Failed to summarize logs: ${error.message}` });
  }
});

app.get('/api/health', async (_req, res) => {
  try {
    const containers = await getContainerList();
    const results = [];

    for (const container of containers) {
      const inspectData = await inspectContainer(container.name);
      const logs = await getContainerLogs(container.name, 200);
      const logSummary = parseLogs(logs);
      const health = scoreContainerHealth(container, inspectData, logSummary);
      const findings = detectCommonIssues(container.name, logs);
      results.push({
        container: container.name,
        status: container.status,
        health,
        logSummary,
        findings
      });
    }

    res.json({ results });
  } catch (error) {
    res.status(500).json({ error: `Failed to compute health: ${error.message}` });
  }
});

app.post('/api/diagnose', async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) {
      return res.status(400).json({ error: 'query is required' });
    }

    const plan = mapQueryToDiagnostics(query);
    const containers = await getContainerList();
    const availableNames = new Set(containers.map((c) => c.name.toLowerCase()));

    const targets = plan.targetContainers.filter((name) =>
      [...availableNames].some((actualName) => actualName.includes(name))
    );

    const diagnostics = [];

    for (const target of targets) {
      const actual = containers.find((c) => c.name.toLowerCase().includes(target));
      if (!actual) continue;

      const logs = await getContainerLogs(actual.name, 250);
      const logSummary = parseLogs(logs);
      const findings = detectCommonIssues(actual.name, logs);
      const inspectData = await inspectContainer(actual.name);
      const health = scoreContainerHealth(actual, inspectData, logSummary);

      diagnostics.push({
        container: actual.name,
        health,
        findings,
        summary: logSummary
      });
    }

    const suggestions = [
      'Run `docker ps --format "table {{.Names}}\t{{.Status}}"` to verify runtime status quickly.',
      'Validate host-to-container path mapping consistency for /mnt/media_drive -> /media.',
      'Use read-only checks first (docker logs, docker inspect, systemctl status) before any restart action.'
    ];

    return res.json({ plan, diagnostics, suggestions });
  } catch (error) {
    return res.status(500).json({ error: `Diagnosis failed: ${error.message}` });
  }
});

app.post('/api/execute', async (req, res) => {
  try {
    const { action, containerName, confirmed } = req.body;

    if (action !== 'restart_container') {
      return res.status(400).json({
        error: 'Only restart_container action is supported for safety.',
        allowedReadOnly: SAFE_READ_ONLY_COMMANDS
      });
    }

    if (!containerName) {
      return res.status(400).json({ error: 'containerName is required.' });
    }

    if (!confirmed) {
      return res.status(400).json({
        error: 'Confirmation required before restart.',
        explanation: `About to run: docker restart ${containerName}`
      });
    }

    const { stdout } = await runCommand('docker', ['restart', containerName]);
    return res.json({
      message: `Restart command executed for ${containerName}`,
      output: stdout.trim(),
      explanation: 'Restart was explicitly user-confirmed before execution.'
    });
  } catch (error) {
    return res.status(500).json({ error: `Execution failed: ${error.message}` });
  }
});

app.get('/api/safety', (_req, res) => {
  res.json({
    allowedReadOnlyCommands: SAFE_READ_ONLY_COMMANDS,
    blockedExamples: ['rm -rf', 'volume deletion', 'firewall rule modifications', 'disk formatting'],
    restartPolicy: 'Restart requires explicit confirmation in /api/execute.'
  });
});


app.get('/api/qbittorrent/torrents', async (_req, res) => {
  try {
    const torrents = await getQbittorrentTorrents();
    res.json({
      source: QBITTORRENT_URL,
      count: torrents.length,
      torrents
    });
  } catch (error) {
    res.status(500).json({
      error: `Failed to read qBittorrent torrents: ${error.message}`,
      hint: 'Set QBITTORRENT_URL and optional QBITTORRENT_USERNAME/QBITTORRENT_PASSWORD for API access.'
    });
  }
});

app.get('/api/system-monitor', async (_req, res) => {
  try {
    const cpuUtilizationPercent = await getCpuUtilization();
    const memory = getMemoryUtilization();
    const storage = await getStorageUtilization('/media');

    res.json({
      cpu: {
        utilizationPercent: cpuUtilizationPercent,
        cores: os.cpus().length
      },
      memory,
      storage,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to read system monitor metrics: ${error.message}` });
  }
});

app.listen(PORT, () => {
  console.log(`Homelab assistant listening on http://localhost:${PORT}`);
});
