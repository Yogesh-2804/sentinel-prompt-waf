import { useState, useRef, useEffect } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { Send, Bot, User, ShieldAlert, Sparkles, AlertCircle, RefreshCw, Lock } from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000/api/v1';

export default function UserChatApp() {
  const [messages, setMessages] = useState([
    {
      id: 'welcome-1',
      sender: 'assistant',
      text: 'Hello! I am SentinelCorp AI Assistant. How can I help you with internal corporate policy, HR guidelines, or IT support today?',
      isBlocked: false,
      timestamp: '09:00 AM'
    }
  ]);
  const [inputPrompt, setInputPrompt] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const chatEndRef = useRef(null);

  const scrollToBottom = () => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  const handleSendMessage = async (textToSend = null) => {
    const promptText = textToSend || inputPrompt;
    if (!promptText.trim() || isLoading) return;

    const userMessageId = `user-${Date.now()}`;
    const userMsg = {
      id: userMessageId,
      sender: 'user',
      text: promptText,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    if (!textToSend) setInputPrompt('');
    setIsLoading(true);

    try {
      const res = await fetch(`${API_BASE_URL}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: promptText, llm_provider: 'ollama' })
      });

      if (!res.ok) {
        throw new Error(`Server status ${res.status}`);
      }

      const data = await res.json();
      const isBlocked = data.security_eval?.verdict === 'BLOCKED' || data.security_report?.status === 'BLOCKED' || data.security_eval?.is_malicious === true;

      let responseText = '';
      if (isBlocked) {
        responseText = data.security_report?.message || 'Security Notice: This request was blocked because it attempts to access restricted, confidential, or unauthorized information.';
      } else {
        const llmResp = data.llm_response;
        if (typeof llmResp === 'string') {
          responseText = llmResp;
        } else if (llmResp && typeof llmResp === 'object') {
          if (llmResp.status === 'service_unavailable' || (llmResp.response_text && llmResp.response_text.startsWith('LLM Service Unavailable'))) {
            responseText = 'The AI service is temporarily unavailable. Please try again later.';
          } else if (llmResp.response_text) {
            responseText = llmResp.response_text;
          } else if (llmResp.text) {
            responseText = llmResp.text;
          } else {
            responseText = "I don't have that information in the current SentinelCorp knowledge base.";
          }
        } else {
          responseText = "I don't have that information in the current SentinelCorp knowledge base.";
        }
      }

      const assistantMsg = {
        id: `asst-${Date.now()}`,
        sender: 'assistant',
        text: responseText,
        isBlocked: isBlocked,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setMessages(prev => [...prev, assistantMsg]);

    } catch (err) {
      console.error(err);
      setMessages(prev => [...prev, {
        id: `asst-${Date.now()}`,
        sender: 'assistant',
        text: 'The AI service is temporarily unavailable. Please try again later.',
        isBlocked: false,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handlePresetClick = (presetText) => {
    handleSendMessage(presetText);
  };

  return (
    <>
      <Head>
        <title>SentinelCorp AI Assistant</title>
        <meta name="description" content="Enterprise AI Assistant for SentinelCorp Employees" />
      </Head>

      <div style={{ display: 'flex', height: '100vh', background: 'var(--bg-dark)', color: 'var(--text-main)', fontFamily: 'var(--font-sans)' }}>
        
        {/* Sidebar */}
        <aside style={{ width: '280px', borderRight: '1px solid var(--border-color)', background: 'rgba(15, 23, 42, 0.95)', padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            {/* Brand Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '24px' }}>
              <div style={{ background: 'linear-gradient(135deg, #3b82f6, #06b6d4)', padding: '8px', borderRadius: '10px', display: 'flex' }}>
                <Bot size={22} color="#ffffff" />
              </div>
              <div>
                <h1 style={{ fontSize: '1.05rem', fontWeight: 700, margin: 0, color: '#f8fafc' }}>SentinelCorp AI</h1>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Employee Assistant v1.0</span>
              </div>
            </div>

            {/* Quick Action Preset Queries */}
            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '10px' }}>
                Suggested Employee Queries
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <button 
                  onClick={() => handlePresetClick("What is SentinelCorp's annual leave policy?")}
                  className="btn-secondary"
                  style={{ justifyContent: 'flex-start', textAlign: 'left', fontSize: '0.8rem', padding: '8px 12px' }}
                >
                  <Sparkles size={14} color="#38bdf8" /> Annual Leave Policy
                </button>
                <button 
                  onClick={() => handlePresetClick("What are the standard working hours?")}
                  className="btn-secondary"
                  style={{ justifyContent: 'flex-start', textAlign: 'left', fontSize: '0.8rem', padding: '8px 12px' }}
                >
                  <Sparkles size={14} color="#38bdf8" /> Standard Working Hours
                </button>
                <button 
                  onClick={() => handlePresetClick("How do I contact IT Support for password resets?")}
                  className="btn-secondary"
                  style={{ justifyContent: 'flex-start', textAlign: 'left', fontSize: '0.8rem', padding: '8px 12px' }}
                >
                  <Sparkles size={14} color="#38bdf8" /> IT Support & Password Resets
                </button>
              </div>
            </div>
          </div>

          {/* Footer & Admin Portal Link */}
          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '16px' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Lock size={12} color="#10b981" /> Protected by SentinelPrompt WAF
            </div>
            <Link 
              href="/admin" 
              style={{ 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center', 
                gap: '8px', 
                width: '100%', 
                padding: '10px', 
                borderRadius: '8px', 
                background: 'rgba(255, 255, 255, 0.05)', 
                color: 'var(--primary-cyan)', 
                textDecoration: 'none', 
                fontSize: '0.8rem', 
                fontWeight: 600,
                border: '1px solid rgba(56, 189, 248, 0.2)'
              }}
            >
              <ShieldAlert size={14} /> Security Admin Console
            </Link>
          </div>
        </aside>

        {/* Main Chat Panel */}
        <main style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100vh', background: 'rgba(10, 15, 30, 0.95)' }}>
          
          {/* Top Bar */}
          <header style={{ padding: '16px 28px', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(15, 23, 42, 0.6)' }}>
            <div>
              <h2 style={{ fontSize: '1rem', fontWeight: 600, margin: 0 }}>Corporate Employee Assistant</h2>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Connected to SentinelCorp Internal Knowledge Base</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.2)', padding: '6px 12px', borderRadius: '20px', fontSize: '0.75rem', color: '#10b981' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981', display: 'inline-block' }}></span>
              WAF Protection Active
            </div>
          </header>

          {/* Messages Container */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            {messages.map((msg) => (
              <div 
                key={msg.id} 
                style={{ 
                  display: 'flex', 
                  flexDirection: 'column', 
                  alignItems: msg.sender === 'user' ? 'flex-end' : 'flex-start' 
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                  {msg.sender === 'assistant' ? (
                    <>
                      <Bot size={16} color={msg.isBlocked ? '#ef4444' : '#38bdf8'} />
                      <span style={{ fontSize: '0.8rem', fontWeight: 600, color: msg.isBlocked ? '#ef4444' : '#38bdf8' }}>
                        {msg.isBlocked ? 'SentinelPrompt Security Gateway' : 'SentinelCorp AI'}
                      </span>
                    </>
                  ) : (
                    <>
                      <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)' }}>You</span>
                      <User size={16} color="var(--text-muted)" />
                    </>
                  )}
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{msg.timestamp}</span>
                </div>

                <div 
                  style={{ 
                    maxWidth: '80%', 
                    padding: '14px 18px', 
                    borderRadius: '12px', 
                    fontSize: '0.9rem', 
                    lineHeight: '1.5',
                    background: msg.sender === 'user' 
                      ? 'linear-gradient(135deg, #2563eb, #1d4ed8)' 
                      : msg.isBlocked 
                        ? 'rgba(239, 68, 68, 0.12)' 
                        : 'var(--card-bg)',
                    border: msg.sender === 'user' 
                      ? 'none' 
                      : msg.isBlocked 
                        ? '1px solid rgba(239, 68, 68, 0.4)' 
                        : '1px solid var(--border-color)',
                    color: msg.isBlocked ? '#fca5a5' : '#f8fafc',
                    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)'
                  }}
                >
                  {msg.isBlocked && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', fontWeight: 700, color: '#ef4444' }}>
                      <ShieldAlert size={18} /> SECURITY VIOLATION DETECTED
                    </div>
                  )}
                  {msg.text}
                </div>
              </div>
            ))}

            {isLoading && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--primary-cyan)', fontSize: '0.85rem' }}>
                <RefreshCw size={16} className="spin" />
                Analyzing prompt via SentinelPrompt Security Gateway...
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Prompt Input Form */}
          <form 
            onSubmit={(e) => { e.preventDefault(); handleSendMessage(); }}
            style={{ padding: '20px 28px', borderTop: '1px solid var(--border-color)', background: 'rgba(15, 23, 42, 0.6)', display: 'flex', gap: '12px', alignItems: 'center' }}
          >
            <input 
              type="text"
              value={inputPrompt}
              onChange={(e) => setInputPrompt(e.target.value)}
              placeholder="Ask a question or enter a prompt..."
              disabled={isLoading}
              style={{ 
                flex: 1, 
                padding: '14px 18px', 
                borderRadius: '10px', 
                background: 'rgba(15, 23, 42, 0.9)', 
                border: '1px solid var(--border-color)', 
                color: '#f8fafc', 
                fontSize: '0.9rem',
                outline: 'none'
              }}
            />
            <button 
              type="submit" 
              disabled={isLoading || !inputPrompt.trim()}
              className="btn-primary"
              style={{ padding: '14px 24px', borderRadius: '10px', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.9rem' }}
            >
              <Send size={16} /> Send
            </button>
          </form>

        </main>
      </div>
    </>
  );
}
