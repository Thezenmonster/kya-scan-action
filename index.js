const core = require('@actions/core');
const fs = require('fs');
const path = require('path');

const KYA_API = 'https://agentscores.xyz/api';

const SEVERITY_ORDER = ['low', 'elevated', 'high', 'critical'];

async function scanPackage(name) {
  try {
    const res = await fetch(`${KYA_API}/scan?npm=${encodeURIComponent(name)}`, {
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return { package: name, error: `HTTP ${res.status}`, risk: 'ERROR' };
    return await res.json();
  } catch (e) {
    return { package: name, error: e.message, risk: 'ERROR' };
  }
}

async function checkAbuse(name) {
  try {
    const res = await fetch(`${KYA_API}/abuse/check?agent=${encodeURIComponent(name)}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function meetsThreshold(risk, threshold) {
  const riskIdx = SEVERITY_ORDER.indexOf(risk.toLowerCase());
  const threshIdx = SEVERITY_ORDER.indexOf(threshold.toLowerCase());
  if (riskIdx === -1 || threshIdx === -1) return false;
  return riskIdx >= threshIdx;
}

async function run() {
  try {
    const failOn = core.getInput('fail-on').toLowerCase();
    const pkgPath = core.getInput('package-json');
    const scanDevDeps = core.getInput('scan-dev-deps') === 'true';

    // Read package.json
    const fullPath = path.resolve(pkgPath);
    if (!fs.existsSync(fullPath)) {
      core.setFailed(`package.json not found at ${fullPath}`);
      return;
    }

    const pkg = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
    const deps = Object.keys(pkg.dependencies || {});
    const devDeps = scanDevDeps ? Object.keys(pkg.devDependencies || {}) : [];
    const allDeps = [...new Set([...deps, ...devDeps])];

    if (allDeps.length === 0) {
      core.info('No dependencies found in package.json');
      core.setOutput('total-scanned', '0');
      core.setOutput('issues-found', '0');
      return;
    }

    core.info(`Scanning ${allDeps.length} dependencies...`);
    core.info('');

    const results = [];
    const issues = [];

    // Scan in batches of 5
    for (let i = 0; i < allDeps.length; i += 5) {
      const batch = allDeps.slice(i, i + 5);
      const scanResults = await Promise.all(batch.map(async (dep) => {
        const [scan, abuse] = await Promise.all([
          scanPackage(dep),
          checkAbuse(dep),
        ]);
        return { dep, scan, abuse };
      }));

      for (const { dep, scan, abuse } of scanResults) {
        const risk = scan.risk || 'ERROR';
        const score = scan.score !== undefined ? scan.score : '?';
        const abuseStatus = abuse ? abuse.status : 'unknown';
        const abuseReports = abuse ? abuse.report_count : 0;

        results.push({ dep, risk, score, abuseStatus, abuseReports, findings: scan.summary?.total_findings || 0 });

        // Check scan risk
        if (risk !== 'LOW' && risk !== 'ERROR') {
          issues.push({ dep, type: 'scan', risk, score, findings: scan.findings || [] });
        }

        // Check abuse status
        if (abuseReports > 0) {
          issues.push({ dep, type: 'abuse', reports: abuseReports, reasons: abuse.reasons || [] });
        }

        // Log each result
        const icon = risk === 'LOW' ? '\u2705' : risk === 'ERROR' ? '\u2753' : '\u274c';
        const abuseIcon = abuseReports > 0 ? ` \u26a0\ufe0f ABUSE: ${abuseReports} reports` : '';
        core.info(`${icon} ${dep} | score: ${score} | risk: ${risk}${abuseIcon}`);
      }
    }

    core.info('');
    core.info(`--- Scanned ${allDeps.length} packages | ${issues.length} issues found ---`);

    // Set outputs
    core.setOutput('total-scanned', String(allDeps.length));
    core.setOutput('issues-found', String(issues.length));
    core.setOutput('report', JSON.stringify({ results, issues }));

    // Create summary
    core.summary
      .addHeading('KYA Security Scan Results')
      .addTable([
        [{ data: 'Package', header: true }, { data: 'Score', header: true }, { data: 'Risk', header: true }, { data: 'Abuse', header: true }],
        ...results.map(r => [
          r.dep,
          String(r.score),
          r.risk,
          r.abuseReports > 0 ? `${r.abuseReports} reports` : 'clean',
        ]),
      ])
      .addLink('Full scan details', 'https://agentscores.xyz/scan');

    if (issues.length > 0) {
      core.summary.addHeading('Issues Found', 3);
      for (const issue of issues) {
        if (issue.type === 'scan') {
          core.summary.addRaw(`**${issue.dep}** - Risk: ${issue.risk} (score: ${issue.score})\n`);
          for (const f of issue.findings) {
            core.summary.addRaw(`  - [${f.severity}] ${f.type}: ${f.detail}\n`);
          }
        } else if (issue.type === 'abuse') {
          core.summary.addRaw(`**${issue.dep}** - ${issue.reports} abuse report(s): ${issue.reasons.join(', ')}\n`);
        }
      }
    }

    await core.summary.write();

    // Fail if any issue meets the threshold
    const shouldFail = issues.some(i => {
      if (i.type === 'abuse') return true; // Always fail on abuse reports
      return meetsThreshold(i.risk, failOn);
    });

    if (shouldFail) {
      core.setFailed(`KYA scan found ${issues.length} issue(s) meeting the '${failOn}' threshold. See scan summary for details.`);
    } else {
      core.info('\nAll dependencies passed KYA security checks.');
    }

  } catch (error) {
    core.setFailed(`KYA scan failed: ${error.message}`);
  }
}

run();
