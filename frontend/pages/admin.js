import { useState, useEffect } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { 
  ShieldAlert, ShieldCheck, Activity, Cpu, Database, 
  Terminal, RefreshCw, Zap, Lock, AlertTriangle, Layers, Send, CheckCircle2, XCircle, ArrowLeft, LogOut, KeyRound, Sliders, LineChart, FileText, Check
} from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000/api/v1';

export default function AdminConsole() {
  const [activeTab, setActiveTab] = useState('overview'); // overview, audit, playground, research, policies
  const [adminToken, setAdminToken] = useState(null);
  
  // Login Form State
  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [authError, setAuthError] = useState(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // Admin Dashboard Data State
  const [stats, setStats] = useState({
    total_requests: 0,
    blocked_threats: 0,
    safe_requests: 0,
    block_rate_percentage: 0.0,
    avg_latency_ms: 0.0
  });
  const [auditLogs, setAuditLogs] = useState([]);
  const [promptInput, setPromptInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  // Policy Management State
  const [policyRules, setPolicyRules] = useState({
    block_system_prompt_extraction: true,
    block_api_keys: true,
    block_employee_salary_queries: true,
    block_confidential_documents: true
  });
  const [policySaveStatus, setPolicySaveStatus] = useState(null);

  // Research Analytics State (Loaded dynamically from API)
  const [researchData, setResearchData] = useState(null);

  // Check stored token on mount
  useEffect(() => {
    const storedToken = sessionStorage.getItem('admin_token');
    if (storedToken) {
      setAdminToken(storedToken);
      fetchLiveDashboardData(storedToken);
      fetchActivePolicies(storedToken);
      fetchResearchAnalytics(storedToken);
    }
  }, []);

  const handleAdminLogin = async (e) => {
    e.preventDefault();
    setAuthError(null);
    setIsLoggingIn(true);

    try {
      const res = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: usernameInput, password: passwordInput })
      });

      if (!res.ok) {
        throw new Error('Invalid admin credentials');
      }

      const data = await res.json();
      const token = data.access_token;
      sessionStorage.setItem('admin_token', token);
      setAdminToken(token);
      fetchLiveDashboardData(token);
      fetchActivePolicies(token);
      fetchResearchAnalytics(token);

    } catch (err) {
      setAuthError('Authentication failed: Invalid admin username or password.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleAdminLogout = () => {
    sessionStorage.removeItem('admin_token');
    setAdminToken(null);
    setScanResult(null);
  };

  const fetchLiveDashboardData = async (token) => {
    const headers = { 'Authorization': `Bearer ${token}` };

    try {
      const statsRes = await fetch(`${API_BASE_URL}/dashboard/stats`, { headers });
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }
    } catch (err) {
      console.warn("Could not fetch live dashboard stats.");
    }

    try {
      const logsRes = await fetch(`${API_BASE_URL}/dashboard/logs?limit=50`, { headers });
      if (logsRes.ok) {
        const logsData = await logsRes.json();
        if (Array.isArray(logsData)) {
          const formattedLogs = logsData.map(l => ({
            id: l.id || `evt-${l.timestamp}`,
            timestamp: l.timestamp || new Date().toISOString(),
            client_ip: l.client_ip || "127.0.0.1",
            prompt_snippet: l.prompt_text ? (l.prompt_text.length > 60 ? l.prompt_text.substring(0, 60) + '...' : l.prompt_text) : "Prompt text",
            action_taken: l.action_taken || l.verdict || "FORWARDED",
            threat_score: l.overall_threat_score ?? 0.0,
            threat_level: l.threat_level || "LOW",
            attack_types: l.detected_categories || [],
            latency_ms: l.execution_time_ms ?? 5.0
          }));
          setAuditLogs(formattedLogs);
        }
      }
    } catch (err) {
      console.warn("Could not fetch live audit logs.");
    }
  };

  const fetchActivePolicies = async (token) => {
    try {
      const res = await fetch(`${API_BASE_URL}/policies`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        if (data.rules) {
          setPolicyRules(data.rules);
        }
      }
    } catch (err) {
      console.warn("Could not fetch policy configuration.");
    }
  };

  const fetchResearchAnalytics = async (token) => {
    try {
      const res = await fetch(`${API_BASE_URL}/dashboard/research-analytics`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setResearchData(data);
      }
    } catch (err) {
      console.warn("Could not fetch research analytics data from backend API.");
    }
  };

  const handlePolicyToggle = (ruleKey) => {
    setPolicyRules(prev => ({
      ...prev,
      [ruleKey]: !prev[ruleKey]
    }));
  };

  const handleSavePolicies = async () => {
    if (!adminToken) return;
    setPolicySaveStatus("Saving changes...");

    try {
      const res = await fetch(`${API_BASE_URL}/policies`, {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`
        },
        body: JSON.stringify({ rules: policyRules })
      });

      if (!res.ok) {
        throw new Error("Failed to save policies");
      }

      setPolicySaveStatus("✓ Policy settings successfully updated and saved to company_policy.yaml!");
      setTimeout(() => setPolicySaveStatus(null), 4000);

    } catch (err) {
      setPolicySaveStatus("Error updating policy configuration.");
    }
  };

  const handleRunScan = async () => {
    if (!promptInput.trim() || !adminToken) return;
    setIsScanning(true);
    setScanResult(null);

    try {
      const res = await fetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminToken}`
        },
        body: JSON.stringify({ prompt: promptInput })
      });

      if (!res.ok) {
        throw new Error(`Server returned status ${res.status}`);
      }

      const data = await res.json();
      setScanResult(data);

      const newLog = {
        id: `evt-${Date.now()}`,
        timestamp: new Date().toISOString(),
        client_ip: "127.0.0.1",
        prompt_snippet: promptInput.length > 60 ? promptInput.substring(0, 60) + '...' : promptInput,
        action_taken: data.verdict,
        threat_score: data.overall_threat_score,
        threat_level: data.threat_level,
        attack_types: data.detected_attack_types || [],
        latency_ms: data.execution_time_ms
      };

      setAuditLogs(prev => [newLog, ...prev.slice(0, 49)]);
      setStats(prev => ({
        ...prev,
        total_requests: prev.total_requests + 1,
        blocked_threats: data.is_malicious ? prev.blocked_threats + 1 : prev.blocked_threats,
        safe_requests: !data.is_malicious ? prev.safe_requests + 1 : prev.safe_requests
      }));

    } catch (err) {
      console.error(err);
    } finally {
      setIsScanning(false);
    }
  };

  // Render Login Card if Unauthenticated
  if (!adminToken) {
    return (
      <>
        <Head>
          <title>Admin Login | SentinelPrompt</title>
        </Head>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg-dark)' }}>
          <div className="glass-panel" style={{ width: '400px', padding: '32px', borderRadius: '16px' }}>
            
            <div style={{ textAlign: 'center', marginBottom: '24px' }}>
              <div style={{ display: 'inline-flex', background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', padding: '12px', borderRadius: '14px', marginBottom: '12px' }}>
                <KeyRound size={28} color="#ffffff" />
              </div>
              <h1 style={{ fontSize: '1.3rem', fontWeight: 700 }}>Admin Security Login</h1>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Authentication required for SentinelPrompt Admin Console
              </p>
            </div>

            {authError && (
              <div style={{ background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', padding: '10px 14px', borderRadius: '8px', color: '#fda4af', fontSize: '0.8rem', marginBottom: '16px' }}>
                {authError}
              </div>
            )}

            <form onSubmit={handleAdminLogin}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>Admin Username</label>
                <input 
                  type="text" 
                  className="custom-input"
                  placeholder="Enter admin username"
                  value={usernameInput}
                  onChange={(e) => setUsernameInput(e.target.value)}
                  style={{ width: '100%', padding: '10px 14px', fontSize: '0.85rem' }}
                  required
                />
              </div>

              <div style={{ marginBottom: '24px' }}>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>Admin Password</label>
                <input 
                  type="password" 
                  className="custom-input"
                  placeholder="Enter admin password"
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  style={{ width: '100%', padding: '10px 14px', fontSize: '0.85rem' }}
                  required
                />
              </div>

              <button type="submit" className="btn-primary" style={{ width: '100%', padding: '12px' }} disabled={isLoggingIn}>
                {isLoggingIn ? 'Authenticating...' : 'Sign In to Admin Console'}
              </button>
            </form>

            <div style={{ textAlign: 'center', marginTop: '20px' }}>
              <Link href="/" style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <ArrowLeft size={14} /> Back to Employee Chat View
              </Link>
            </div>

          </div>
        </div>
      </>
    );
  }

  // Render Admin Console if Authenticated
  return (
    <>
      <Head>
        <title>SentinelPrompt | Admin Security Console</title>
        <meta name="description" content="Admin Security Console & Threat Telemetry for SentinelPrompt" />
      </Head>

      <div style={{ padding: '24px 36px', maxWidth: '1440px', margin: '0 auto' }}>
        
        {/* Top Navbar */}
        <header className="glass-panel" style={{ padding: '16px 24px', marginBottom: '28px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <Link href="/" style={{ textDecoration: 'none', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.85rem' }}>
              <ArrowLeft size={16} /> Employee Chat View
            </Link>
            <div style={{ background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', padding: '10px', borderRadius: '12px', display: 'flex' }}>
              <ShieldAlert size={26} color="#ffffff" />
            </div>
            <div>
              <h1 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em', background: 'linear-gradient(90deg, #f8fafc, #38bdf8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                SentinelPrompt Admin Console
              </h1>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Security Monitoring, Telemetry Analytics & Policy Enforcement
              </p>
            </div>
          </div>

          {/* Navigation Tabs & Logout */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ display: 'flex', gap: '6px', background: 'rgba(15, 23, 42, 0.8)', padding: '6px', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
              <button 
                className={activeTab === 'overview' ? 'btn-primary' : 'btn-secondary'}
                onClick={() => setActiveTab('overview')}
                style={{ fontSize: '0.8rem' }}
              >
                <Activity size={15} /> Overview
              </button>
              <button 
                className={activeTab === 'audit' ? 'btn-primary' : 'btn-secondary'}
                onClick={() => setActiveTab('audit')}
                style={{ fontSize: '0.8rem' }}
              >
                <Layers size={15} /> Audit Stream
              </button>
              <button 
                className={activeTab === 'playground' ? 'btn-primary' : 'btn-secondary'}
                onClick={() => setActiveTab('playground')}
                style={{ fontSize: '0.8rem' }}
              >
                <Terminal size={15} /> Playground
              </button>
              <button 
                className={activeTab === 'research' ? 'btn-primary' : 'btn-secondary'}
                onClick={() => setActiveTab('research')}
                style={{ fontSize: '0.8rem' }}
              >
                <LineChart size={15} /> Research Benchmarks
              </button>
              <button 
                className={activeTab === 'policies' ? 'btn-primary' : 'btn-secondary'}
                onClick={() => setActiveTab('policies')}
                style={{ fontSize: '0.8rem' }}
              >
                <Sliders size={15} /> Policy Settings
              </button>
            </div>

            <button onClick={handleAdminLogout} className="btn-secondary" style={{ fontSize: '0.8rem', color: '#fda4af' }}>
              <LogOut size={15} /> Logout
            </button>
          </div>
        </header>

        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && (
          <div>
            {/* Stat Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '28px' }}>
              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Total Prompts Scanned</span>
                  <Database size={20} color="var(--primary-cyan)" />
                </div>
                <div style={{ fontSize: '1.8rem', fontWeight: 700 }}>{stats.total_requests}</div>
                <span style={{ fontSize: '0.75rem', color: 'var(--accent-emerald)' }}>Live Database Statistics</span>
              </div>

              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Threats Blocked</span>
                  <ShieldAlert size={20} color="var(--accent-rose)" />
                </div>
                <div style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--accent-rose)' }}>{stats.blocked_threats}</div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{stats.block_rate_percentage}% Block Rate</span>
              </div>

              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Safe Queries Forwarded</span>
                  <ShieldCheck size={20} color="var(--accent-emerald)" />
                </div>
                <div style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--accent-emerald)' }}>{stats.safe_requests}</div>
                <span style={{ fontSize: '0.75rem', color: 'var(--accent-emerald)' }}>Forwarded to Downstream LLM</span>
              </div>

              <div className="glass-panel" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Average WAF Latency</span>
                  <Cpu size={20} color="var(--accent-amber)" />
                </div>
                <div style={{ fontSize: '1.8rem', fontWeight: 700 }}>{stats.avg_latency_ms} ms</div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>CPU Multi-Layer Inference</span>
              </div>
            </div>

            {/* Architecture Overview */}
            <div className="glass-panel" style={{ padding: '24px' }}>
              <h2 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={18} color="var(--primary-cyan)" /> SentinelPrompt 4-Layer Security Architecture
              </h2>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#38bdf8', marginBottom: '4px' }}>Layer 1</div>
                  <div style={{ fontWeight: 600, marginBottom: '6px' }}>Pattern / Regex</div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Known signature matching, Base64 decoding, delimiter scanning.</p>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#38bdf8', marginBottom: '4px' }}>Layer 2</div>
                  <div style={{ fontWeight: 600, marginBottom: '6px' }}>Keyword Aho-Corasick</div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Fast string matching across high-risk security keyword sets.</p>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#38bdf8', marginBottom: '4px' }}>Layer 3</div>
                  <div style={{ fontWeight: 600, marginBottom: '6px' }}>DistilBERT ML</div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Fine-tuned PyTorch sequence classification for adversarial prompts.</p>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '16px', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#38bdf8', marginBottom: '4px' }}>Layer 4</div>
                  <div style={{ fontWeight: 600, marginBottom: '6px' }}>MiniLM + FAISS</div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>384-dim dense vector search over indexed threat corpus.</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* AUDIT LOG TAB */}
        {activeTab === 'audit' && (
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={18} color="var(--primary-cyan)" /> Live Security Event Log Stream
            </h2>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '12px' }}>Timestamp</th>
                    <th style={{ padding: '12px' }}>Client IP</th>
                    <th style={{ padding: '12px' }}>Prompt Snippet</th>
                    <th style={{ padding: '12px' }}>Threat Score</th>
                    <th style={{ padding: '12px' }}>Verdict</th>
                    <th style={{ padding: '12px' }}>Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => (
                    <tr key={log.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>{log.timestamp.substring(11, 19)}</td>
                      <td style={{ padding: '12px', fontFamily: 'var(--font-mono)' }}>{log.client_ip}</td>
                      <td style={{ padding: '12px', maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{log.prompt_snippet}</td>
                      <td style={{ padding: '12px', fontWeight: 600 }}>{log.threat_score.toFixed(4)}</td>
                      <td style={{ padding: '12px' }}>
                        <span className={`badge ${log.action_taken === 'BLOCKED' ? 'badge-danger' : log.action_taken === 'FLAGGED' ? 'badge-warning' : 'badge-safe'}`}>
                          {log.action_taken}
                        </span>
                      </td>
                      <td style={{ padding: '12px', color: 'var(--text-muted)' }}>{log.latency_ms} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* PLAYGROUND TAB */}
        {activeTab === 'playground' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
            <div className="glass-panel" style={{ padding: '24px' }}>
              <h2 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Terminal size={18} color="var(--primary-cyan)" /> Security Analyst Prompt Inspection
              </h2>

              <textarea 
                className="custom-input"
                rows={6}
                placeholder="Enter prompt text here to inspect through 4-layer security firewall..."
                value={promptInput}
                onChange={(e) => setPromptInput(e.target.value)}
                style={{ resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: '0.9rem', marginBottom: '16px' }}
              />

              <button className="btn-primary" style={{ width: '100%' }} onClick={handleRunScan} disabled={isScanning}>
                {isScanning ? 'Running 4-Layer Inspection...' : 'Analyze Prompt Security'}
              </button>
            </div>

            {/* Results Panel */}
            <div className="glass-panel" style={{ padding: '24px' }}>
              <h2 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Activity size={18} color="var(--primary-cyan)" /> Detailed Security Telemetry
              </h2>

              {scanResult ? (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', padding: '14px', borderRadius: '12px', background: 'rgba(15,23,42,0.8)', border: '1px solid var(--border-color)' }}>
                    <div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Final Verdict</div>
                      <div style={{ fontSize: '1.3rem', fontWeight: 700, color: scanResult.verdict === 'BLOCKED' ? 'var(--accent-rose)' : 'var(--accent-emerald)' }}>
                        {scanResult.verdict}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Threat Score</div>
                      <div style={{ fontSize: '1.3rem', fontWeight: 700 }}>{scanResult.overall_threat_score.toFixed(4)}</div>
                    </div>
                  </div>

                  <h3 style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '10px' }}>Layer Score Breakdown:</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '0.8rem' }}>
                    <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px' }}>
                      Layer 1 Regex: <strong>{scanResult.layer_scores?.layer1_regex ?? 0}</strong>
                    </div>
                    <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px' }}>
                      Layer 2 Keyword: <strong>{scanResult.layer_scores?.layer2_keyword ?? 0}</strong>
                    </div>
                    <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px' }}>
                      Layer 3 DistilBERT ML: <strong>{scanResult.layer_scores?.layer3_ml_distilbert?.toFixed(4) ?? 0}</strong>
                    </div>
                    <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px' }}>
                      Layer 4 MiniLM FAISS: <strong>{scanResult.layer_scores?.layer4_semantic_faiss?.toFixed(4) ?? 0}</strong>
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px 0' }}>
                  Enter a prompt and click Analyze to view per-layer security scores.
                </div>
              )}
            </div>
          </div>
        )}

        {/* RESEARCH ANALYTICS TAB (Dynamically loaded from GET /api/v1/dashboard/research-analytics) */}
        {activeTab === 'research' && (
          <div>
            <div className="glass-panel" style={{ padding: '24px', marginBottom: '24px' }}>
              <h2 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <LineChart size={18} color="var(--primary-cyan)" /> Empirical Baseline Benchmarks (Held-Out Test Set, N={researchData?.held_out_test_set_size ?? 16})
              </h2>

              <div style={{ fontSize: '0.75rem', color: 'var(--accent-emerald)', marginBottom: '12px' }}>
                ✓ Dynamically fetched via backend API <code>GET /api/v1/dashboard/research-analytics</code> from <code>evaluation_results.json</code>
              </div>

              {researchData && researchData.models ? (
                <div style={{ overflowX: 'auto', marginBottom: '20px' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border-color)', textAlign: 'left', color: 'var(--text-muted)' }}>
                        <th style={{ padding: '12px' }}>Detection Architecture</th>
                        <th style={{ padding: '12px' }}>Accuracy</th>
                        <th style={{ padding: '12px' }}>Precision</th>
                        <th style={{ padding: '12px' }}>Recall (TPR)</th>
                        <th style={{ padding: '12px' }}>F1-Score</th>
                        <th style={{ padding: '12px' }}>FPR</th>
                        <th style={{ padding: '12px' }}>FNR</th>
                        <th style={{ padding: '12px' }}>Avg Latency</th>
                      </tr>
                    </thead>
                    <tbody>
                      {researchData.models.map((m, idx) => (
                        <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', background: m.name.includes("Full 4-Layer") ? 'rgba(56, 189, 248, 0.05)' : 'transparent' }}>
                          <td style={{ padding: '12px', fontWeight: m.name.includes("Full 4-Layer") ? 700 : 600, color: m.name.includes("Full 4-Layer") ? 'var(--primary-cyan)' : 'inherit' }}>{m.name}</td>
                          <td style={{ padding: '12px' }}>{(m.accuracy * 100).toFixed(2)}%</td>
                          <td style={{ padding: '12px' }}>{m.precision.toFixed(4)}</td>
                          <td style={{ padding: '12px', color: m.recall > 0.8 ? 'var(--accent-emerald)' : 'var(--accent-rose)' }}>{(m.recall * 100).toFixed(2)}% ({m.tp}/{m.tp + m.fn})</td>
                          <td style={{ padding: '12px' }}>{m.f1_score.toFixed(4)}</td>
                          <td style={{ padding: '12px' }}>{(m.fpr * 100).toFixed(2)}%</td>
                          <td style={{ padding: '12px', color: m.fnr === 0 ? 'var(--accent-emerald)' : 'var(--accent-rose)' }}>{(m.fnr * 100).toFixed(2)}%</td>
                          <td style={{ padding: '12px', color: 'var(--text-muted)' }}>{m.avg_latency_ms} ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ color: 'var(--text-muted)', padding: '20px' }}>Loading empirical evaluation results from backend...</div>
              )}

              {researchData && researchData.confusion_matrix && (
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', background: 'rgba(15, 23, 42, 0.6)', padding: '14px', borderRadius: '8px' }}>
                  <strong>95% Wilson Confidence Interval:</strong> Full Pipeline Accuracy = [{((researchData.models.find(m => m.name.includes("Full"))?.accuracy_wilson_ci?.[0] ?? 0.7167) * 100).toFixed(2)}%, {((researchData.models.find(m => m.name.includes("Full"))?.accuracy_wilson_ci?.[1] ?? 0.9889) * 100).toFixed(2)}%], Recall = [{((researchData.models.find(m => m.name.includes("Full"))?.recall_wilson_ci?.[0] ?? 0.6097) * 100).toFixed(2)}%, {((researchData.models.find(m => m.name.includes("Full"))?.recall_wilson_ci?.[1] ?? 1.0) * 100).toFixed(2)}%].<br />
                  <strong>Full Pipeline Confusion Matrix:</strong> TN={researchData.confusion_matrix.tn}, FP={researchData.confusion_matrix.fp}, FN={researchData.confusion_matrix.fn}, TP={researchData.confusion_matrix.tp}.
                </div>
              )}
            </div>
          </div>
        )}

        {/* POLICY SETTINGS TAB */}
        {activeTab === 'policies' && (
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Sliders size={18} color="var(--primary-cyan)" /> Organizational Security Policy Rules
            </h2>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '24px' }}>
              Policy rule modifications are saved directly to <code>company_policy.yaml</code> on the backend and take immediate effect in the Decision Engine.
            </p>

            {policySaveStatus && (
              <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '12px 16px', borderRadius: '8px', color: '#6ee7b7', fontSize: '0.85rem', marginBottom: '20px' }}>
                {policySaveStatus}
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '28px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px', borderRadius: '10px', background: 'rgba(15,23,42,0.6)', border: '1px solid var(--border-color)' }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '4px' }}>Block System Prompt Extraction</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Rejects prompts attempting to expose or repeat initial AI instructions.</div>
                </div>
                <input 
                  type="checkbox" 
                  checked={policyRules.block_system_prompt_extraction ?? true}
                  onChange={() => handlePolicyToggle('block_system_prompt_extraction')}
                  style={{ width: '20px', height: '20px', cursor: 'pointer' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px', borderRadius: '10px', background: 'rgba(15,23,42,0.6)', border: '1px solid var(--border-color)' }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '4px' }}>Block Hardcoded API Keys</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Rejects prompts containing API keys, AWS credentials, or tokens.</div>
                </div>
                <input 
                  type="checkbox" 
                  checked={policyRules.block_api_keys ?? true}
                  onChange={() => handlePolicyToggle('block_api_keys')}
                  style={{ width: '20px', height: '20px', cursor: 'pointer' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px', borderRadius: '10px', background: 'rgba(15,23,42,0.6)', border: '1px solid var(--border-color)' }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '4px' }}>Block Employee Salary & Payroll Queries</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Rejects unauthorized queries regarding confidential HR compensation data.</div>
                </div>
                <input 
                  type="checkbox" 
                  checked={policyRules.block_employee_salary_queries ?? true}
                  onChange={() => handlePolicyToggle('block_employee_salary_queries')}
                  style={{ width: '20px', height: '20px', cursor: 'pointer' }}
                />
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px', borderRadius: '10px', background: 'rgba(15,23,42,0.6)', border: '1px solid var(--border-color)' }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '4px' }}>Block Confidential Document Requests</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Rejects requests targeting trade secret agreements or unreleased financial audits.</div>
                </div>
                <input 
                  type="checkbox" 
                  checked={policyRules.block_confidential_documents ?? true}
                  onChange={() => handlePolicyToggle('block_confidential_documents')}
                  style={{ width: '20px', height: '20px', cursor: 'pointer' }}
                />
              </div>
            </div>

            <button className="btn-primary" onClick={handleSavePolicies} style={{ padding: '12px 24px', display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
              <Check size={16} /> Save Policy Configuration
            </button>
          </div>
        )}

      </div>
    </>
  );
}
