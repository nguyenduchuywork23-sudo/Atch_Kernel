import { useState, useEffect } from 'react';
import './App.css';
import { Bridge, HostEventType, ClientCommandType } from './Bridge';
import { getExam, submitExam, login, getSessions, getLogs, getUsers, getConfig, saveConfig, unlockExam, postSecurityLog } from './api';

// ─── Type definitions ─────────────────────────────────────────────────────────
interface ScanEvent {
  pid: number;
  imageName: string;
  imagePath: string;
  verdict: 'TRUSTED' | 'SUSPICIOUS' | 'MALICIOUS';
  signed: boolean;
  sha256: string;
  sentToRing0: boolean;
  timestamp: string;
}

interface ViolationEvent {
  type: string;
  process: string;
}

interface ExamOption {
  id: string;
  text: string;
}

interface ExamQuestion {
  id: string;
  text: string;
  options: ExamOption[];
}

interface ExamData {
  id: string;
  title: string;
  duration: number;
  code: string;
  questions: ExamQuestion[];
}

// ─── Main App ─────────────────────────────────────────────────────────────────
function App() {
  const [isDriverLoaded, setIsDriverLoaded]   = useState(false);
  const [examStarted,    setExamStarted]       = useState(false);
  const [violation,      setViolation]         = useState<ViolationEvent | null>(null);
  const [integrityFail,  setIntegrityFail]     = useState<string | null>(null);
  const [scanLog,        setScanLog]           = useState<ScanEvent[]>([]);
  const [invalidEnv,     setInvalidEnv]        = useState(false);
  const [showLogin,      setShowLogin]         = useState(false);
  const [userRole,       setUserRole]          = useState<'student' | 'teacher' | 'admin' | null>(null);
  const [username,       setUsername]          = useState('');
  const [password,       setPassword]          = useState('');
  const [sessions,       setSessions]          = useState<any[]>([]);
  const [teacherLogs,    setTeacherLogs]       = useState<any[]>([]);
  const [adminUsers,     setAdminUsers]        = useState<any[]>([]);
  const [targetExamUrl,  setTargetExamUrl]     = useState('');
  const [configMessage,  setConfigMessage]     = useState('');
  const [searchQuery,    setSearchQuery]       = useState('');
  const [selectedStudent, setSelectedStudent]  = useState<any>(null);
  const [teacherRooms]                         = useState([
    { id: 'R101', name: 'Phòng Thi 101', capacity: 40, currentStudents: 38, status: 'Active' },
    { id: 'R102', name: 'Phòng Thi 102', capacity: 40, currentStudents: 40, status: 'Active' },
    { id: 'R103', name: 'Phòng Thi 103', capacity: 35, currentStudents: 0, status: 'Pending' }
  ]);
  const [teacherSchedule]                      = useState([
    { id: 'E1', name: 'An Toàn Thông Tin - Cuối Kỳ', time: '08:00 - 10:00', date: '25/07/2026', room: 'Phòng Thi 101' },
    { id: 'E2', name: 'Mạng Máy Tính', time: '13:00 - 15:00', date: '25/07/2026', room: 'Phòng Thi 102' }
  ]);
  // ─── Exam States ────────────────────────────────────────────────────────────
  const [examData, setExamData] = useState<ExamData | null>(null);
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [examSubmitted, setExamSubmitted] = useState(false);
  const [examScore, setExamScore] = useState<number | null>(null);
  const [timeLeft, setTimeLeft] = useState(60 * 60); // 60 minutes default
  const [examUnlocked, setExamUnlocked] = useState(false);

  // ─── Heartbeat ──────────────────────────────────────────────────────────────
  useEffect(() => {
    if (examStarted && userRole === 'student') {
      const interval = setInterval(() => {
        Bridge.postMessage(ClientCommandType.HEARTBEAT, { status: 'ALIVE' });
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [examStarted, userRole]);

  // ─── Timer ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (examStarted && userRole === 'student' && !examSubmitted && timeLeft > 0) {
      const timer = setTimeout(() => setTimeLeft(t => t - 1), 1000);
      return () => clearTimeout(timer);
    } else if (timeLeft === 0 && !examSubmitted) {
      handleSubmitExam(); // Auto-submit when time is up
    }
  }, [examStarted, userRole, timeLeft, examSubmitted]);

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60).toString().padStart(2, '0');
    const s = (seconds % 60).toString().padStart(2, '0');
    return `${m}:${s}`;
  };

  useEffect(() => {
    // Kiosk Mode Check: Ngăn chặn chạy trên trình duyệt web thông thường
    if (!window.chrome || !(window.chrome as any).webview) {
      setInvalidEnv(true);
      return;
    }

    Bridge.addListener((message) => {
      switch (message.type) {

        case HostEventType.DRIVER_INITIALIZED:
          setIsDriverLoaded(true);
          break;

        case HostEventType.DRIVER_LOST:
          setViolation({ type: 'Mất kết nối Driver', process: 'Ring0_CoreDriver.sys' });
          break;

        case HostEventType.VIOLATION_DETECTED:
          const violationData = {
            type:    message.payload?.violationType ?? 'UNKNOWN',
            process: message.payload?.processName   ?? 'Unknown Process',
          };
          setViolation(violationData);
          
          postSecurityLog('VIOLATION_DETECTED', violationData).catch(console.error);
          break;

        case HostEventType.INTEGRITY_FAIL:
          setIntegrityFail(message.payload?.reason ?? 'Unknown integrity failure');
          break;

        case HostEventType.SCAN_RESULT:
          const scanEvent: ScanEvent = {
            pid:        message.payload.pid,
            imageName:  message.payload.imageName,
            imagePath:  message.payload.imagePath,
            verdict:    message.payload.verdict,
            signed:     message.payload.signed,
            sha256:     message.payload.sha256,
            sentToRing0: message.payload.sentToRing0,
            timestamp:  new Date().toLocaleTimeString('vi-VN'),
          };
          setScanLog(prev => [scanEvent, ...prev].slice(0, 50)); 
          
          postSecurityLog('SCAN_RESULT', scanEvent).catch(console.error);

          if (message.payload.verdict === 'MALICIOUS') {
            setViolation({
              type:    'Phần mềm độc hại phát hiện bởi Ring 3',
              process: message.payload.imageName,
            });
          }
          break;

        case HostEventType.EXAM_UNLOCKED:
          setExamUnlocked(true);
          break;
      }
    });

    // Giả lập load driver thành công sau 1.5s cho mượt
    const timer = setTimeout(() => setIsDriverLoaded(true), 1500);
    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (userRole === 'teacher') {
      const fetchDashboard = async () => {
        try {
          const [sessRes, logsRes] = await Promise.all([
            getSessions(),
            getLogs()
          ]);
          setSessions(sessRes);
          setTeacherLogs(logsRes);
        } catch (error) {
          console.error("Failed to fetch dashboard data:", error);
        }
      };
      
      fetchDashboard();
      const interval = setInterval(fetchDashboard, 3000);
      return () => clearInterval(interval);
    }
  }, [userRole]);

  useEffect(() => {
    if (userRole === 'admin') {
      const fetchUsers = async () => {
        try {
          const res = await getUsers();
          setAdminUsers(res);
        } catch (error) {
          console.error("Failed to fetch users:", error);
        }
      };
      
      fetchUsers();
    }
  }, [userRole]);

  useEffect(() => {
    if (examStarted && userRole === 'student') {
      getConfig()
        .then(data => {
            if (data && data.targetExamUrl) {
                setTargetExamUrl(data.targetExamUrl);
                setExamUnlocked(true); // Tự động hiển thị đề thi nếu Admin đã cấu hình link
            }
        })
        .catch(err => console.error('Failed to load exam config', err));
    }
  }, [examStarted, userRole, examUnlocked]);

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.hidden && examStarted && userRole === 'student') {
        const violationData = {
          type: 'Chuyển tab hoặc thu nhỏ trình duyệt',
          process: 'Trình duyệt / Hệ điều hành'
        };
        setViolation(violationData);
        
        postSecurityLog('VIOLATION_DETECTED', violationData).catch(console.error);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [examStarted, userRole]);

  const handleProceedToLogin = () => {
    setShowLogin(true);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const data = await login({ username, password });
      setUserRole(data.role);
      if (data.token) localStorage.setItem('token', data.token);
      setShowLogin(false);
      if (data.role === 'student') {
        Bridge.postMessage(ClientCommandType.START_EXAM, { sessionToken: data.sessionToken || 'EXAM_2026_XYZ' });
        setExamStarted(true);
        try {
          const exam = await getExam('001');
          setExamData(exam);
          if (exam.duration) setTimeLeft(exam.duration * 60);
        } catch (err) {
          console.error("Failed to load exam", err);
        }
        if (document.documentElement.requestFullscreen) {
          document.documentElement.requestFullscreen().catch(err => console.error('Fullscreen API error:', err));
        }
      }
    } catch (err) {
      alert('Sai tên đăng nhập hoặc mật khẩu!');
    }
  };

  const handleSubmitExam = async () => {
    if (!examData) return;
    try {
      const result = await submitExam(examData.id, { answers });
      setExamSubmitted(true);
      if (result && result.score !== undefined) {
        setExamScore(result.score);
      }
    } catch (err) {
      console.error('Submit failed', err);
      alert('Nộp bài thất bại!');
    }
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await saveConfig('target_exam_url', targetExamUrl);
      setConfigMessage('Cập nhật cấu hình thành công!');
      setTimeout(() => setConfigMessage(''), 3000);
    } catch (err) {
      console.error(err);
      setConfigMessage('Cập nhật thất bại!');
    }
  };

  const handleUnlockExam = async () => {
    try {
      await unlockExam();
      alert('Exam unlocked successfully!');
    } catch (err) {
      console.error(err);
      alert('Failed to unlock exam!');
    }
  };

  const handleLogout = () => {
    setUserRole(null);
    setExamStarted(false);
    setUsername('');
    setPassword('');
    setSelectedStudent(null);
    Bridge.postMessage(ClientCommandType.END_EXAM);
  };

  // ─── Helpers ──────────────────────────────────────────────────────────────
  const getVerdictColor = (verdict: string) => {
    if (verdict === 'TRUSTED') return 'var(--success)';
    if (verdict === 'MALICIOUS') return 'var(--danger)';
    return 'var(--warning)';
  };

  const getVerdictIcon = (verdict: string) => {
    if (verdict === 'TRUSTED') return '✓';
    if (verdict === 'MALICIOUS') return '✗';
    return '⚠';
  };

  // ─── Màn hình Lỗi Môi trường ──────────────────────────────────────────────
  if (invalidEnv) {
    return (
      <div className="app-container">
        <div className="alert-overlay animate-fade-in">
          <div className="alert-box">
            <div className="alert-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
              </svg>
            </div>
            <h2 className="alert-title">Lỗi Môi Trường</h2>
            <p className="subtitle" style={{ color: 'var(--text-main)' }}>
              Không thể truy cập trực tiếp bài thi qua trình duyệt web thông thường.
            </p>
            <div className="status-box" style={{ marginTop: '24px', textAlign: 'left', background: 'rgba(0,0,0,0.4)' }}>
              <div className="status-item">
                <span className="status-label">Lý do:</span>
                <span className="status-value status-error">Thiếu Module WebView2 Host</span>
              </div>
              <div className="status-item" style={{ borderBottom: 'none' }}>
                <span className="status-label">Yêu cầu:</span>
                <span className="status-value text-muted">Mở bằng Atch_Kernel_Client.exe</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ─── Màn hình Cảnh báo Vi phạm ────────────────────────────────────────────
  if (violation || integrityFail) {
    const isIntegrity = !!integrityFail;
    const title = isIntegrity ? "Vi phạm Toàn vẹn Hệ thống!" : "Phát hiện Gian lận!";
    const desc = isIntegrity 
      ? "Bộ kiểm tra toàn vẹn Ring 3 đã phát hiện hành vi can thiệp vào phần mềm."
      : "Hệ thống đã tự động khóa bài thi và báo cáo hành vi khả nghi.";

    return (
      <div className="app-container">
        <div className="alert-overlay-danger animate-fade-in">
          <div className="alert-box">
            <div className="alert-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
                <path d="M12 9v4"/><path d="M12 17h.01"/>
              </svg>
            </div>
            <h2 className="alert-title">{title}</h2>
            <p className="subtitle" style={{ color: 'var(--text-main)' }}>{desc}</p>
            <div className="status-box" style={{ marginTop: '24px', textAlign: 'left', background: 'rgba(0,0,0,0.4)' }}>
              {isIntegrity ? (
                <div className="status-item" style={{ borderBottom: 'none' }}>
                  <span className="status-label">Chi tiết:</span>
                  <span className="status-value status-error" style={{ wordBreak: 'break-all', fontSize: '12px' }}>
                    {integrityFail}
                  </span>
                </div>
              ) : (
                <>
                  <div className="status-item">
                    <span className="status-label">Loại vi phạm:</span>
                    <span className="status-value status-error">{violation?.type}</span>
                  </div>
                  <div className="status-item" style={{ borderBottom: 'none' }}>
                    <span className="status-label">Tiến trình:</span>
                    <span className="status-value">{violation?.process}</span>
                  </div>
                </>
              )}
            </div>
            <button className="alert-btn" onClick={() => Bridge.postMessage(ClientCommandType.END_EXAM)}>
              Thoát Hệ thống
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ─── Màn hình Bài thi ─────────────────────────────────────────────────────
  if (examStarted) {
    const suspiciousCount = scanLog.filter(e => e.verdict === 'SUSPICIOUS').length;
    
    return (
      <div className="exam-container animate-fade-in" onCopy={(e) => e.preventDefault()} onPaste={(e) => e.preventDefault()}>
        <div className="exam-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div className="status-dot" style={{ background: 'var(--success)', boxShadow: '0 0 10px var(--success)' }}></div>
            <h2 style={{ margin: 0, fontSize: '18px', letterSpacing: '1px' }}>ATCH EXAM PORTAL</h2>
            <span style={{ color: 'var(--accent)', fontSize: '12px', padding: '4px 10px', background: 'rgba(56,189,248,0.1)', borderRadius: '6px', border: '1px solid rgba(56,189,248,0.3)' }} className="mono">
              SESSION: EXAM_2026_XYZ
            </span>
          </div>
          <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
            {suspiciousCount > 0 && (
              <span style={{ color: 'var(--warning)', fontSize: '13px', background: 'rgba(245,158,11,0.1)', padding: '6px 12px', borderRadius: '8px', border: '1px solid var(--warning)' }}>
                ⚠ {suspiciousCount} Warn
              </span>
            )}
            <div style={{ marginRight: '16px', textAlign: 'right' }}>
              <div style={{ fontSize: '14px', fontWeight: 'bold' }}>Sinh Viên</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Mã SV: 2026001</div>
            </div>
            <button style={{ background: 'transparent', color: 'var(--text-muted)', fontSize: '14px', border: '1px solid var(--glass-border)', padding: '6px 16px', borderRadius: '8px' }} onClick={handleLogout}>
              ĐĂNG XUẤT
            </button>
          </div>
        </div>

        {/* Real Exam Content */}
        <div className="exam-content">
          {!examUnlocked ? (
            <div style={{ textAlign: 'center', padding: '100px 20px', color: 'var(--text-muted)' }}>
              <h2>Đang chờ Giảng viên mở khóa bài thi...</h2>
              <p>Vui lòng không đóng cửa sổ này.</p>
              <div className="status-dot" style={{ background: 'var(--warning)', marginTop: '20px', width: '20px', height: '20px', display: 'inline-block' }}></div>
            </div>
          ) : targetExamUrl ? (
            <iframe 
              src={targetExamUrl}
              style={{ width: '100%', height: '100%', minHeight: '600px', border: 'none', borderRadius: '12px' }}
              title="Exam Content"
            />
          ) : (
          <div className="mock-exam-paper">
            <div className="mock-exam-title">
              <div>
                <h1 style={{ color: 'var(--primary)', marginBottom: '8px' }}>{examData?.title || 'Bài thi Trắc nghiệm'}</h1>
                <p style={{ color: 'var(--text-muted)' }}>Thời gian: {examData ? examData.duration : 60} phút | Mã đề: {examData?.code || '001'}</p>
              </div>
              <div className="timer-box">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                </svg>
                {formatTime(timeLeft)}
              </div>
            </div>

            {examSubmitted ? (
              <div style={{ textAlign: 'center', padding: '60px 20px' }}>
                <div className="status-dot" style={{ background: 'var(--success)', width: '60px', height: '60px', margin: '0 auto 20px', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 30px var(--success-glow)' }}>
                  <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                </div>
                <h2 style={{ fontSize: '24px', color: 'var(--success)', marginBottom: '10px' }}>Đã nộp bài thành công!</h2>
                <p style={{ color: 'var(--text-muted)' }}>Cảm ơn bạn đã hoàn thành bài thi. Kết quả đã được lưu trữ an toàn.</p>
              </div>
            ) : examData ? (
              <>
                {examData.questions.map((q, idx) => (
                  <div key={q.id} className="mock-question">
                    <h3>Câu {idx + 1}: {q.text}</h3>
                    <div className="mock-options">
                      {q.options.map(opt => (
                        <label key={opt.id} className={`mock-option ${answers[q.id] === opt.id ? 'selected' : ''}`}>
                          <input 
                            type="radio" 
                            name={q.id} 
                            checked={answers[q.id] === opt.id} 
                            onChange={() => setAnswers({...answers, [q.id]: opt.id})} 
                          /> {opt.text}
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
                
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '40px' }}>
                  <button className="primary-btn" style={{ width: '200px' }} onClick={handleSubmitExam}>
                    NỘP BÀI
                  </button>
                </div>
              </>
            ) : (
              <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--text-muted)' }}>
                Đang tải đề thi...
              </div>
            )}
          </div>
          )}
        </div>

        {/* Scanner Log Terminal */}
        <div className="terminal-log">
          <div className="terminal-header">
            <span>// KERNEL SCANNER LOG</span>
            <span className="live-indicator"><span className="status-dot" style={{ background: 'var(--success)' }}></span> LIVE</span>
          </div>
          <div className="terminal-content">
            {scanLog.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontStyle: 'italic', textAlign: 'center', padding: '20px 0' }}>
                Đang chờ sự kiện quét...
              </div>
            ) : (
              scanLog.map((ev, idx) => (
                <div key={idx} className="terminal-entry">
                  <div style={{ flex: 1, display: 'flex', gap: '8px' }}>
                    <span className="terminal-verdict" style={{ color: getVerdictColor(ev.verdict) }}>
                      [{getVerdictIcon(ev.verdict)}]
                    </span>
                    <span style={{ color: '#e2e8f0', wordBreak: 'break-all' }}>{ev.imageName}</span>
                  </div>
                  <span style={{ color: 'var(--text-muted)', fontSize: '10px', marginLeft: '10px', whiteSpace: 'nowrap' }}>
                    {ev.timestamp}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    );
  }

  // ─── Màn hình Login ───────────────────────────────────────────────────────
  if (showLogin) {
    return (
      <div className="app-container">
        <form className="glass-panel lock-screen" onSubmit={handleLogin}>
          <div className="lock-icon-wrapper">
            <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/>
            </svg>
          </div>
          <div>
            <h1 className="title">ĐĂNG NHẬP</h1>
            <p className="subtitle">Hệ thống Thi Trực Tuyến An Toàn</p>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', textAlign: 'left', marginTop: '10px' }}>
            <div>
              <label style={{ fontSize: '14px', color: 'var(--text-muted)', marginBottom: '8px', display: 'block' }}>Tên đăng nhập (giangvien/sinhvien/admin)</label>
              <input type="text" className="input-field" value={username} onChange={e => setUsername(e.target.value)} required />
            </div>
            <div>
              <label style={{ fontSize: '14px', color: 'var(--text-muted)', marginBottom: '8px', display: 'block' }}>Mật khẩu (123456)</label>
              <input type="password" className="input-field" value={password} onChange={e => setPassword(e.target.value)} required />
            </div>
          </div>
          <button type="submit" className="primary-btn" style={{ marginTop: '10px' }}>
            ĐĂNG NHẬP
          </button>
        </form>
      </div>
    );
  }

  // ─── Màn hình Giảng viên ──────────────────────────────────────────────────
  if (userRole === 'teacher') {
    return (
      <div className="exam-container animate-fade-in">
        <div className="exam-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div className="status-dot" style={{ background: 'var(--success)', boxShadow: '0 0 10px var(--success)' }}></div>
            <h2 style={{ margin: 0, fontSize: '18px', letterSpacing: '1px' }}>ATCH EXAM PORTAL - TEACHER</h2>
          </div>
          <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
            <div style={{ marginRight: '16px', textAlign: 'right' }}>
              <div style={{ fontSize: '14px', fontWeight: 'bold' }}>Giảng Viên</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Khoa ATTT</div>
            </div>
            <button style={{ background: 'var(--success)', color: '#fff', fontSize: '14px', border: 'none', padding: '6px 16px', borderRadius: '8px', cursor: 'pointer' }} onClick={handleUnlockExam}>
              Unlock Exam
            </button>
            <button style={{ background: 'transparent', color: 'var(--text-muted)', fontSize: '14px', border: '1px solid var(--glass-border)', padding: '6px 16px', borderRadius: '8px' }} onClick={handleLogout}>
              ĐĂNG XUẤT
            </button>
          </div>
        </div>
        {selectedStudent ? (
          <div className="dashboard-container">
            <button 
              onClick={() => setSelectedStudent(null)} 
              style={{ 
                marginBottom: '16px', 
                background: 'transparent', 
                border: '1px solid var(--glass-border)', 
                color: 'var(--text-main)', 
                padding: '8px 16px', 
                borderRadius: '8px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
              className="hover-effect"
            >
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
              Quay lại Dashboard
            </button>
            <div className="card" style={{ width: '100%' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
                <div className="status-dot" style={{ background: selectedStudent.status === 'BLOCKED' ? 'var(--danger)' : 'var(--success)' }}></div>
                <h3 className="card-title" style={{ margin: 0, padding: 0, border: 'none' }}>
                  Chi tiết logs: {selectedStudent.studentName || 'Unknown'} (MSSV: {selectedStudent.studentId || 'N/A'})
                </h3>
              </div>
              <div className="terminal-content" style={{ maxHeight: '600px', overflowY: 'auto' }}>
                {teacherLogs.filter(ev => !ev.studentId || ev.studentId === selectedStudent.studentId || ev.sessionToken === selectedStudent.sessionToken).length === 0 ? (
                  <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontStyle: 'italic', textAlign: 'center', padding: '20px 0' }}>
                    Chưa có sự kiện nào được ghi nhận cho sinh viên này...
                  </div>
                ) : (
                  teacherLogs.filter(ev => !ev.studentId || ev.studentId === selectedStudent.studentId || ev.sessionToken === selectedStudent.sessionToken).map((ev, idx) => (
                    <div key={idx} className="terminal-entry" style={{ padding: '8px 0', borderBottom: '1px dashed rgba(255,255,255,0.05)' }}>
                      <div style={{ flex: 1, display: 'flex', gap: '8px' }}>
                        <span className="terminal-verdict" style={{ color: getVerdictColor(ev.verdict) }}>
                          [{getVerdictIcon(ev.verdict)}]
                        </span>
                        <span style={{ color: '#e2e8f0', wordBreak: 'break-all', fontSize: '13px' }}>{ev.imageName || ev.process} {ev.pid ? `(PID: ${ev.pid})` : ''}</span>
                      </div>
                      <span style={{ color: 'var(--text-muted)', fontSize: '11px', whiteSpace: 'nowrap' }}>
                        {ev.timestamp}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="dashboard-container">
            <div className="dashboard-grid">
              <div className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <h3 className="card-title" style={{ margin: 0, borderBottom: 'none', paddingBottom: 0 }}>Danh sách Sinh viên đang thi</h3>
                  <div style={{ position: 'relative' }}>
                    <input 
                      type="text" 
                      placeholder="Tìm kiếm sinh viên..." 
                      className="input-field" 
                      style={{ width: '250px', padding: '8px 12px', fontSize: '13px', paddingLeft: '32px' }}
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }}>
                      <circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>
                    </svg>
                  </div>
                </div>
                <div className="student-list">
                  {sessions.filter(s => 
                    (s.studentName || 'Unknown').toLowerCase().includes(searchQuery.toLowerCase()) || 
                    (String(s.studentId || '')).toLowerCase().includes(searchQuery.toLowerCase())
                  ).length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '13px', padding: '10px' }}>Không tìm thấy sinh viên nào.</div>
                  ) : (
                    sessions.filter(s => 
                      (s.studentName || 'Unknown').toLowerCase().includes(searchQuery.toLowerCase()) || 
                      (String(s.studentId || '')).toLowerCase().includes(searchQuery.toLowerCase())
                    ).map((s, idx) => (
                      <div key={idx} className="student-item" style={{ ...(s.status === 'BLOCKED' ? { borderColor: 'var(--danger-glow)', background: 'rgba(239, 68, 68, 0.05)' } : {}), cursor: 'pointer' }} onClick={() => setSelectedStudent(s)}>
                        <div className="student-info">
                          <span className="student-name">{s.studentName || 'Unknown'}</span>
                          <span className="student-id">MSSV: {s.studentId || 'N/A'}</span>
                        </div>
                        {s.status === 'BLOCKED' ? (
                          <span className="status-value status-error"><div className="status-dot"></div> Bị khóa (Vi phạm)</span>
                        ) : (
                          <span className="status-value status-ok"><div className="status-dot"></div> Đang làm bài</span>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
              
              <div className="card">
                <h3 className="card-title">Nhật ký Giám sát (Kernel Scanner)</h3>
                <div className="terminal-content" style={{ maxHeight: '400px', overflowY: 'auto' }}>
                  {teacherLogs.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '12px', fontStyle: 'italic', textAlign: 'center', padding: '20px 0' }}>
                      Chưa có sự kiện nào được ghi nhận...
                    </div>
                  ) : (
                    teacherLogs.map((ev, idx) => (
                      <div key={idx} className="terminal-entry" style={{ padding: '8px 0', borderBottom: '1px dashed rgba(255,255,255,0.05)' }}>
                        <div style={{ flex: 1, display: 'flex', gap: '8px' }}>
                          <span className="terminal-verdict" style={{ color: getVerdictColor(ev.verdict) }}>
                            [{getVerdictIcon(ev.verdict)}]
                          </span>
                          <span style={{ color: '#e2e8f0', wordBreak: 'break-all', fontSize: '13px' }}>{ev.imageName || ev.process} {ev.pid ? `(PID: ${ev.pid})` : ''}</span>
                        </div>
                        <span style={{ color: 'var(--text-muted)', fontSize: '11px', whiteSpace: 'nowrap' }}>
                          {ev.timestamp}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="card">
                <h3 className="card-title">Danh sách Phòng Thi</h3>
                <div className="student-list" style={{ maxHeight: '400px', overflowY: 'auto' }}>
                  {teacherRooms.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '13px', padding: '10px' }}>Chưa có phòng thi nào.</div>
                  ) : (
                    teacherRooms.map((r, idx) => (
                      <div key={idx} className="student-item">
                        <div className="student-info">
                          <span className="student-name">{r.name}</span>
                          <span className="student-id">Mã phòng: {r.id} | Sĩ số: {r.currentStudents}/{r.capacity}</span>
                        </div>
                        {r.status === 'Active' ? (
                          <span className="status-value status-ok"><div className="status-dot"></div> Đang thi</span>
                        ) : (
                          <span className="status-value status-pending" style={{ color: '#f59e0b' }}><div className="status-dot" style={{ background: '#f59e0b' }}></div> Chờ thi</span>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="card">
                <h3 className="card-title">Lịch Gác Thi</h3>
                <div className="student-list" style={{ maxHeight: '400px', overflowY: 'auto' }}>
                  {teacherSchedule.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '13px', padding: '10px' }}>Chưa có lịch gác thi.</div>
                  ) : (
                    teacherSchedule.map((s, idx) => (
                      <div key={idx} className="student-item" style={{ alignItems: 'flex-start', flexDirection: 'column', gap: '8px' }}>
                        <div className="student-info" style={{ width: '100%' }}>
                          <span className="student-name" style={{ fontSize: '15px' }}>{s.name}</span>
                          <span className="student-id" style={{ marginTop: '4px' }}>Mã ca thi: {s.id}</span>
                        </div>
                        <div style={{ display: 'flex', gap: '16px', fontSize: '13px', color: 'var(--text-muted)' }}>
                          <span><strong style={{ color: '#fff' }}>Thời gian:</strong> {s.time}</span>
                          <span><strong style={{ color: '#fff' }}>Ngày:</strong> {s.date}</span>
                          <span><strong style={{ color: '#fff' }}>Phòng:</strong> {s.room}</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  // ─── Màn hình Admin ─────────────────────────────────────────────────────────
  if (userRole === 'admin') {
    return (
      <div className="exam-container animate-fade-in">
        <div className="exam-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div className="status-dot" style={{ background: 'var(--success)', boxShadow: '0 0 10px var(--success)' }}></div>
            <h2 style={{ margin: 0, fontSize: '18px', letterSpacing: '1px' }}>ATCH EXAM PORTAL - ADMIN DASHBOARD</h2>
          </div>
          <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
            <div style={{ marginRight: '16px', textAlign: 'right' }}>
              <div style={{ fontSize: '14px', fontWeight: 'bold' }}>Quản Trị Viên</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Hệ Thống</div>
            </div>
            <button style={{ background: 'transparent', color: 'var(--text-muted)', fontSize: '14px', border: '1px solid var(--glass-border)', padding: '6px 16px', borderRadius: '8px' }} onClick={handleLogout}>
              ĐĂNG XUẤT
            </button>
          </div>
        </div>
        <div className="dashboard-container">
          <div className="card">
            <h3 className="card-title">Cấu hình Hệ thống</h3>
            <form onSubmit={handleSaveConfig} style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div>
                <label style={{ fontSize: '14px', color: 'var(--text-muted)', marginBottom: '8px', display: 'block' }}>Target Exam URL</label>
                <input type="text" className="input-field" value={targetExamUrl} onChange={e => setTargetExamUrl(e.target.value)} placeholder="https://example.com/exam" required />
              </div>
              <button type="submit" className="primary-btn" style={{ width: 'fit-content' }}>Lưu cấu hình</button>
              {configMessage && <div style={{ fontSize: '13px', color: configMessage.includes('thành công') ? 'var(--success)' : 'var(--danger)' }}>{configMessage}</div>}
            </form>
          </div>
          <div className="card">
            <h3 className="card-title">Quản lý Người dùng</h3>
            <div className="student-list">
              {adminUsers.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', fontSize: '13px', padding: '10px' }}>Chưa có người dùng nào.</div>
              ) : (
                adminUsers.map((u, idx) => (
                  <div key={idx} className="student-item">
                    <div className="student-info">
                      <span className="student-name">{u.username}</span>
                      <span className="student-id">Vai trò: {u.role}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ─── Màn hình Khởi động ───────────────────────────────────────────────────
  return (
    <div className="app-container">
      <div className="glass-panel lock-screen">
        <div className="lock-icon-wrapper">
          <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <div>
          <h1 className="title">ATCH KERNEL</h1>
          <p className="subtitle">Secure Exam Environment Initialization</p>
        </div>
        <div className="status-box">
          <div className="status-item">
            <span className="status-label">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              Trạng thái Ring 3
            </span>
            <span className="status-value status-ok"><div className="status-dot"></div> Sẵn sàng</span>
          </div>
          <div className="status-item">
            <span className="status-label">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              Kết nối Kernel (Ring 0)
            </span>
            <span className={`status-value ${isDriverLoaded ? 'status-ok' : 'status-wait'}`}>
              <div className="status-dot"></div> {isDriverLoaded ? 'Đã kết nối' : 'Đang thiết lập...'}
            </span>
          </div>
          <div className="status-item">
            <span className="status-label">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
              Bộ quét động (Dynamic Scanner)
            </span>
            <span className={`status-value ${isDriverLoaded ? 'status-ok' : 'status-wait'}`}>
              <div className="status-dot"></div> {isDriverLoaded ? 'Hoạt động' : 'Chờ Driver...'}
            </span>
          </div>
        </div>
        <button className="primary-btn" disabled={!isDriverLoaded} onClick={handleProceedToLogin}>
          {isDriverLoaded ? 'Đăng Nhập Hệ Thống' : 'Hệ Thống Đang Khởi Tạo...'}
        </button>
      </div>
    </div>
  );
}

export default App;
