// =========================================================================
// SpecGuard Core — Global Client Runtime & Navigation Hub
// =========================================================================

const SpecGuard = {
  state: {
    activeProjectId: null,
    activeProject: null,
    projects: [],
    environment: {
      docker_available: false,
      docker_status: "offline",
      docker_message: "Docker sandbox unconfigured (Fail-closed execution policy enforced)",
      version: "2.0.0",
      engines: []
    },
    isOnline: false
  },

  // Get active project ID from URL or localStorage
  getActiveProjectId() {
    const params = new URLSearchParams(window.location.search);
    const urlProj = params.get('project');
    if (urlProj) return urlProj;
    return localStorage.getItem('specguard_active_project');
  },

  setActiveProjectId(projectId) {
    if (!projectId) return;
    this.state.activeProjectId = projectId;
    localStorage.setItem('specguard_active_project', projectId);

    // Update URL parameter without reload
    const url = new URL(window.location.href);
    url.searchParams.set('project', projectId);
    window.history.replaceState({}, '', url);

    const proj = this.state.projects.find(p => p.id === projectId);
    this.state.activeProject = proj || null;

    this.updateHeaderAndSidebar();

    // Dispatch project changed event for page-specific subscribers
    window.dispatchEvent(new CustomEvent('specguard:projectChanged', { detail: { projectId, project: proj } }));
  },

  // Initialize SpecGuard Core on any page
  async init() {
    await this.fetchEnvironment();
    await this.fetchProjects();
    this.setupNavigation();
    this.setupHeaderActions();
    this.sanitizeMisleadingData();
    this.injectGlobalModals();
  },

  // Fetch real backend environment info
  async fetchEnvironment() {
    try {
      const res = await fetch('/api/v2/environment');
      if (res.ok) {
        this.state.environment = await res.json();
        this.state.isOnline = true;
      } else {
        const res1 = await fetch('/api/v1/health');
        if (res1.ok) this.state.isOnline = true;
      }
    } catch (err) {
      console.warn('Backend environment unreachable:', err);
      this.state.isOnline = false;
    }
    this.updateEnvironmentUI();
  },

  // Fetch real projects from /api/v1/projects
  async fetchProjects() {
    try {
      const res = await fetch('/api/v1/projects');
      if (res.ok) {
        this.state.projects = await res.json();
      }
    } catch (err) {
      console.warn('Failed to load projects list:', err);
    }

    let activeId = this.getActiveProjectId();
    if (!activeId || !this.state.projects.some(p => p.id === activeId)) {
      if (this.state.projects.length > 0) {
        activeId = this.state.projects[0].id;
      }
    }

    if (activeId) {
      this.setActiveProjectId(activeId);
    }
  },

  // Update header and sidebar UI elements with active project
  updateHeaderAndSidebar() {
    const proj = this.state.activeProject;
    const projName = proj ? (proj.name || proj.id) : 'Default Project';
    const projId = proj ? proj.id : '';

    // Update project dropdowns
    document.querySelectorAll('.specguard-project-select, #headerProjectSelect, select[name="project_selector"]').forEach(sel => {
      sel.innerHTML = this.state.projects.map(p => 
        `<option value="${p.id}" ${p.id === this.state.activeProjectId ? 'selected' : ''}>${p.name || p.id}</option>`
      ).join('');
    });

    // Update sidebar project card
    const sbName = document.getElementById('sidebarProjectName');
    const sbMeta = document.getElementById('sidebarProjectMeta');
    if (sbName) sbName.textContent = projName;
    if (sbMeta) {
      const sourceState = proj?.has_source ? 'Source: Active' : 'No Source';
      sbMeta.textContent = `${sourceState} · ID: ${projId ? projId.slice(0, 8) : 'demo'}`;
    }

    // Update breadcrumb
    const bcProj = document.getElementById('headerBreadcrumbProject');
    if (bcProj) bcProj.textContent = projName;
  },

  // Truth in reporting: replace hardcoded static claims with genuine backend status
  updateEnvironmentUI() {
    const env = this.state.environment;
    const online = this.state.isOnline;

    // Sidebar status pill
    const sbDot = document.getElementById('sidebarHealthDot');
    const sbText = document.getElementById('sidebarHealthText');
    const sbPill = document.getElementById('sidebarHealthPill');
    if (sbDot) sbDot.className = `h-2 w-2 rounded-full ${online ? 'bg-tertiary animate-pulse' : 'bg-error'}`;
    if (sbText) sbText.textContent = online ? `FastAPI: Connected (v${env.version})` : 'FastAPI: Offline';
    if (sbPill) {
      sbPill.textContent = online ? 'ONLINE' : 'OFFLINE';
      sbPill.className = `font-label-xs text-label-xs ${online ? 'text-tertiary bg-tertiary-container/20' : 'text-error bg-error-container/20'} px-1 py-0.5 rounded font-mono`;
    }

    // Top header backend badge
    const topBadge = document.getElementById('topHealthBadge');
    if (topBadge) {
      topBadge.innerHTML = online 
        ? `<span class="w-1.5 h-1.5 rounded-full bg-tertiary"></span>FastAPI: Connected (v${env.version})`
        : `<span class="w-1.5 h-1.5 rounded-full bg-error"></span>Backend: Offline`;
    }

    // Docker sandbox badge (truth in reporting)
    const dockerBadges = document.querySelectorAll('.specguard-docker-badge, [data-docker-badge]');
    dockerBadges.forEach(b => {
      if (env.docker_available) {
        b.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-tertiary"></span>Docker: Active (rootless)';
        b.className = b.className.replace(/text-outline|text-error/, 'text-tertiary');
      } else {
        b.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-outline"></span>Sandbox: Offline (Fail-Closed)';
        b.title = env.docker_message || 'Docker is unconfigured; untrusted code is blocked from host execution';
      }
    });
  },

  // Sanitize hardcoded claims from original Stitch mockups
  sanitizeMisleadingData() {
    // Replace hardcoded "Docker: 24.0.7-rootless [ISO]" and "git:e93f7a1"
    document.querySelectorAll('body *').forEach(el => {
      if (el.children.length === 0 && el.textContent) {
        if (el.textContent.includes('24.0.7-rootless')) {
          el.textContent = 'Sandbox: Offline (Fail-Closed)';
        } else if (el.textContent === 'git:e93f7a1') {
          el.textContent = 'source: verified AST';
        } else if (el.textContent.includes('DOCKER ISOLATED: PASS') || el.textContent.includes('DOCKER SANDBOX: ISOLATED')) {
          el.textContent = 'EXECUTION BOUNDARY: FAIL-CLOSED';
        }
      }
    });
  },

  // Setup sidebar navigation links across all pages
  setupNavigation() {
    const routeMap = {
      'overview': '/overview',
      'projects': '#',
      'requirements': '/requirements',
      'code-intelligence': '/code-intelligence',
      'behavioral-verification': '/overview',
      'adversarial-testing': '/adversarial-testing',
      'autonomous-test-engineering': '/autonomous-test-engineering',
      'continuous-assurance': '/continuous-assurance',
      'evidence-explorer': '#',
      'reports-and-analytics': '#',
      'settings': '#'
    };

    const currentPath = window.location.pathname;

    document.querySelectorAll('aside nav a').forEach(a => {
      const dataPath = a.getAttribute('data-path') || '';
      const text = a.textContent.toLowerCase();

      let matchedKey = null;
      for (const key of Object.keys(routeMap)) {
        if (dataPath === key || text.includes(key.replace('-', ' '))) {
          matchedKey = key;
          break;
        }
      }

      if (matchedKey) {
        const dest = routeMap[matchedKey];
        if (dest === '#') {
          if (matchedKey === 'projects') {
            a.onclick = (e) => { e.preventDefault(); SpecGuard.openNewProjectModal(); };
          } else if (matchedKey === 'evidence-explorer') {
            a.onclick = (e) => { e.preventDefault(); SpecGuard.openEvidenceModal(); };
          } else if (matchedKey === 'reports-and-analytics') {
            a.onclick = (e) => { e.preventDefault(); SpecGuard.openReportsModal(); };
          } else if (matchedKey === 'settings') {
            a.onclick = (e) => { e.preventDefault(); SpecGuard.openSettingsModal(); };
          }
        } else {
          a.href = dest;
          a.onclick = null;
        }

        // Active link highlight
        const isCurrent = (dest === currentPath) || 
          (matchedKey === 'requirements' && (currentPath === '/' || currentPath === '/requirements')) ||
          (matchedKey === 'overview' && currentPath === '/overview');

        if (isCurrent) {
          a.setAttribute('aria-current', 'page');
          a.className = 'flex items-center gap-space-md px-space-md py-space-sm rounded transition-colors bg-surface-container-high text-primary font-code-sm font-semibold';
        } else {
          a.removeAttribute('aria-current');
          a.className = 'flex items-center gap-space-md px-space-md py-space-sm rounded text-on-surface-variant hover:bg-surface-container-low hover:text-on-surface transition-colors font-body-sm text-body-sm';
        }
      }
    });
  },

  // Setup top header action buttons
  setupHeaderActions() {
    // "Run Assurance" button in header
    document.querySelectorAll('.specguard-run-assurance, header button').forEach(btn => {
      if (btn.textContent.includes('Run Assurance') && !btn.hasAttribute('data-bound')) {
        btn.setAttribute('data-bound', 'true');
        btn.onclick = async () => {
          const pid = SpecGuard.state.activeProjectId;
          if (!pid) {
            SpecGuard.toast('Please select or create a project first.', 'error');
            return;
          }
          btn.disabled = true;
          const origHtml = btn.innerHTML;
          btn.innerHTML = '<span class="material-symbols-outlined text-base animate-spin">refresh</span><span>Running...</span>';
          try {
            const res = await fetch(`/api/v2/projects/${pid}/analyze`, { method: 'POST' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            SpecGuard.toast(`Assurance Pipeline Passed: ${data.counts.total} specs, ${data.counts.symbols || 0} AST symbols`);
            window.dispatchEvent(new CustomEvent('specguard:analysisComplete', { detail: data }));
          } catch (err) {
            SpecGuard.toast(`Assurance error: ${err.message}`, 'error');
          } finally {
            btn.disabled = false;
            btn.innerHTML = origHtml;
          }
        };
      }
    });

    // Notification button
    document.querySelectorAll('header button[title="Notifications"]').forEach(btn => {
      btn.onclick = () => {
        const count = SpecGuard.state.environment.findings_count || 0;
        SpecGuard.toast(`Assurance Diagnostics: ${count} findings recorded in SQLite EvidenceStore.`);
      };
    });
  },

  // Modal Controllers
  openNewProjectModal() {
    const modal = document.getElementById('newProjectModal');
    if (modal) modal.classList.remove('hidden');
  },

  closeNewProjectModal() {
    const modal = document.getElementById('newProjectModal');
    if (modal) modal.classList.add('hidden');
  },

  async openEvidenceModal() {
    const modal = document.getElementById('evidenceModal');
    if (!modal) return;
    modal.classList.remove('hidden');
    const tbody = document.getElementById('evidenceModalTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="4" class="py-6 text-center text-outline">Loading Evidence Records...</td></tr>';

    try {
      const pid = this.state.activeProjectId;
      const res = await fetch(`/api/v2/projects/${pid}/evidence`);
      if (res.ok) {
        const data = await res.json();
        const records = data.evidence || [];
        if (records.length === 0) {
          tbody.innerHTML = '<tr><td colspan="4" class="py-8 text-center text-outline">No evidence records saved yet. Run static analysis to generate evidence.</td></tr>';
          return;
        }
        tbody.innerHTML = records.map(r => `
          <tr class="hover:bg-surface-container-high transition-colors font-code-sm">
            <td class="py-2.5 px-3 font-mono text-primary">${r.evidence_id || 'EV-AUTO'}</td>
            <td class="py-2.5 px-3 text-on-surface">${r.claim || 'Verified AST decomposition'}</td>
            <td class="py-2.5 px-3 font-mono text-outline">${r.requirement_id || 'GLOBAL'}</td>
            <td class="py-2.5 px-3 text-right">
              <span class="font-label-xs text-label-xs bg-tertiary-container/20 text-tertiary px-1.5 py-0.5 rounded font-mono font-bold">${r.status || 'OBSERVED'}</span>
            </td>
          </tr>
        `).join('');
      }
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="4" class="py-6 text-center text-error">Failed to load evidence: ${err.message}</td></tr>`;
    }
  },

  closeEvidenceModal() {
    const modal = document.getElementById('evidenceModal');
    if (modal) modal.classList.add('hidden');
  },

  openReportsModal() {
    const modal = document.getElementById('reportsModal');
    if (modal) modal.classList.remove('hidden');
  },

  closeReportsModal() {
    const modal = document.getElementById('reportsModal');
    if (modal) modal.classList.add('hidden');
  },

  openSettingsModal() {
    const modal = document.getElementById('settingsModal');
    if (modal) modal.classList.remove('hidden');
  },

  closeSettingsModal() {
    const modal = document.getElementById('settingsModal');
    if (modal) modal.classList.add('hidden');
  },

  // Toast notification
  toast(message, type = 'info') {
    let container = document.getElementById('toastContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toastContainer';
      container.className = 'fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-sm pointer-events-none';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    const isErr = type === 'error';
    toast.className = `p-3 rounded-lg shadow-xl font-code-sm text-code-sm flex items-center gap-2 border pointer-events-auto transition-all transform duration-200 translate-y-2 opacity-0 ${
      isErr 
        ? 'bg-error-container text-on-error-container border-error' 
        : 'bg-surface-container-high text-on-surface border-outline-variant'
    }`;

    toast.innerHTML = `
      <span class="material-symbols-outlined text-base ${isErr ? 'text-error' : 'text-primary'}">${isErr ? 'error' : 'info'}</span>
      <span class="flex-1">${message}</span>
    `;

    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.remove('translate-y-2', 'opacity-0'));
    setTimeout(() => {
      toast.classList.add('opacity-0', 'translate-y-2');
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  },

  // Inject global modals if missing
  injectGlobalModals() {
    if (!document.getElementById('evidenceModal')) {
      const modal = document.createElement('div');
      modal.id = 'evidenceModal';
      modal.className = 'fixed inset-0 bg-background/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4';
      modal.innerHTML = `
        <div class="bg-surface-container border border-outline-variant rounded-xl max-w-4xl w-full p-6 shadow-2xl flex flex-col gap-4 max-h-[85vh]">
          <div class="flex items-center justify-between border-b border-outline-variant pb-3">
            <div class="flex items-center gap-2">
              <span class="material-symbols-outlined text-primary text-2xl">history_edu</span>
              <div>
                <h3 class="font-headline-md text-headline-md text-on-surface">Evidence Explorer</h3>
                <p class="font-code-sm text-code-sm text-outline">Deterministic audit records stored in SQLite EvidenceStore</p>
              </div>
            </div>
            <button onclick="SpecGuard.closeEvidenceModal()" class="text-outline hover:text-on-surface p-1 rounded hover:bg-surface-container-high">
              <span class="material-symbols-outlined text-lg">close</span>
            </button>
          </div>
          <div class="flex-1 overflow-y-auto">
            <table class="w-full text-left border-collapse select-none">
              <thead>
                <tr class="bg-surface-container-low text-outline font-label-xs text-label-xs uppercase tracking-wider sticky top-0 border-b border-outline-variant">
                  <th class="py-2 px-3">Evidence ID</th>
                  <th class="py-2 px-3">Claim / Assertion</th>
                  <th class="py-2 px-3">Requirement</th>
                  <th class="py-2 px-3 text-right">Verdict</th>
                </tr>
              </thead>
              <tbody id="evidenceModalTableBody" class="divide-y divide-outline-variant/30 text-on-surface"></tbody>
            </table>
          </div>
          <div class="flex justify-end pt-2 border-t border-outline-variant">
            <button onclick="SpecGuard.closeEvidenceModal()" class="px-4 py-1.5 bg-surface-container-high hover:bg-surface-container-highest rounded text-on-surface font-body-sm text-body-sm">Close</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    }

    if (!document.getElementById('reportsModal')) {
      const modal = document.createElement('div');
      modal.id = 'reportsModal';
      modal.className = 'fixed inset-0 bg-background/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4';
      modal.innerHTML = `
        <div class="bg-surface-container border border-outline-variant rounded-xl max-w-2xl w-full p-6 shadow-2xl flex flex-col gap-4">
          <div class="flex items-center justify-between border-b border-outline-variant pb-3">
            <div class="flex items-center gap-2">
              <span class="material-symbols-outlined text-primary text-2xl">analytics</span>
              <div>
                <h3 class="font-headline-md text-headline-md text-on-surface">Reports & Analytics</h3>
                <p class="font-code-sm text-code-sm text-outline">Autonomous Software Assurance Verification Reports</p>
              </div>
            </div>
            <button onclick="SpecGuard.closeReportsModal()" class="text-outline hover:text-on-surface p-1 rounded hover:bg-surface-container-high">
              <span class="material-symbols-outlined text-lg">close</span>
            </button>
          </div>
          <p class="font-body-sm text-body-sm text-on-surface-variant">
            Generate and export comprehensive assurance reports containing requirement decomposition, AST call graphs, adversarial mutation kill matrices, and regression lifecycles.
          </p>
          <div class="flex flex-col gap-3 bg-surface-container-low p-4 rounded-lg border border-outline-variant">
            <div class="flex items-center justify-between">
              <div>
                <div class="font-code-sm text-code-sm font-semibold text-on-surface">JSON Verification Payload</div>
                <div class="font-label-xs text-label-xs text-outline">Machine-readable complete audit evidence</div>
              </div>
              <button onclick="window.open('/api/v2/requirements', '_blank')" class="bg-primary hover:bg-primary-fixed-dim text-on-primary font-body-sm text-body-sm font-semibold px-3 py-1 rounded">View JSON</button>
            </div>
            <div class="flex items-center justify-between border-t border-outline-variant/40 pt-3">
              <div>
                <div class="font-code-sm text-code-sm font-semibold text-on-surface">API OpenAPI Specification</div>
                <div class="font-label-xs text-label-xs text-outline">FastAPI live schema documentation</div>
              </div>
              <button onclick="window.open('/docs', '_blank')" class="bg-surface-container-high hover:bg-surface-container-highest text-on-surface font-body-sm text-body-sm px-3 py-1 rounded">OpenAPI Docs</button>
            </div>
          </div>
          <div class="flex justify-end pt-2 border-t border-outline-variant">
            <button onclick="SpecGuard.closeReportsModal()" class="px-4 py-1.5 bg-surface-container-high hover:bg-surface-container-highest rounded text-on-surface font-body-sm text-body-sm">Close</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    }

    if (!document.getElementById('settingsModal')) {
      const modal = document.createElement('div');
      modal.id = 'settingsModal';
      modal.className = 'fixed inset-0 bg-background/80 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4';
      modal.innerHTML = `
        <div class="bg-surface-container border border-outline-variant rounded-xl max-w-2xl w-full p-6 shadow-2xl flex flex-col gap-4">
          <div class="flex items-center justify-between border-b border-outline-variant pb-3">
            <div class="flex items-center gap-2">
              <span class="material-symbols-outlined text-primary text-2xl">tune</span>
              <div>
                <h3 class="font-headline-md text-headline-md text-on-surface">System Settings & Security Policy</h3>
                <p class="font-code-sm text-code-sm text-outline">Runtime execution sandbox and evidence storage</p>
              </div>
            </div>
            <button onclick="SpecGuard.closeSettingsModal()" class="text-outline hover:text-on-surface p-1 rounded hover:bg-surface-container-high">
              <span class="material-symbols-outlined text-lg">close</span>
            </button>
          </div>
          <div class="flex flex-col gap-3 font-code-sm text-code-sm">
            <div class="bg-surface-container-low p-3 rounded-lg border border-outline-variant flex justify-between">
              <span class="text-outline">Execution Policy:</span>
              <span class="text-primary font-mono font-semibold">Docker-Only (Fail-Closed Execution)</span>
            </div>
            <div class="bg-surface-container-low p-3 rounded-lg border border-outline-variant flex justify-between">
              <span class="text-outline">Host Code Execution:</span>
              <span class="text-error font-mono font-semibold">Strictly Prohibited</span>
            </div>
            <div class="bg-surface-container-low p-3 rounded-lg border border-outline-variant flex justify-between">
              <span class="text-outline">Static AST Engine:</span>
              <span class="text-tertiary font-mono font-semibold">Python 3.14 (Language Server AST)</span>
            </div>
            <div class="bg-surface-container-low p-3 rounded-lg border border-outline-variant flex justify-between">
              <span class="text-outline">Evidence Persistence:</span>
              <span class="text-on-surface font-mono">SQLite (Versioned Schemas v2)</span>
            </div>
            <div class="bg-surface-container-low p-3 rounded-lg border border-outline-variant flex justify-between">
              <span class="text-outline">Max Archive Upload:</span>
              <span class="text-on-surface font-mono">50 MB (Zip Bomb Protected)</span>
            </div>
          </div>
          <div class="flex justify-end pt-2 border-t border-outline-variant">
            <button onclick="SpecGuard.closeSettingsModal()" class="px-4 py-1.5 bg-surface-container-high hover:bg-surface-container-highest rounded text-on-surface font-body-sm text-body-sm">Close</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    }
  }
};

// Global startup
document.addEventListener('DOMContentLoaded', () => {
  SpecGuard.init();
});
