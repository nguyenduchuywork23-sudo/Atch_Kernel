import { useState, useEffect } from 'react';
import './App.css';
import { Bridge, HostEventType, ClientCommandType } from './Bridge';

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

// ─── Main App ─────────────────────────────────────────────────────────────────
function App() {
  const [isDriverLoaded, setIsDriverLoaded]   = useState(false);
  const [examStarted,    setExamStarted]       = useState(false);
  const [violation,      setViolation]         = useState<ViolationEvent | null>(null);
  const [integrityFail,  setIntegrityFail]     = useState<string | null>(null);
  const [scanLog,        setScanLog]           = useState<ScanEvent[]>([]);
  const [invalidEnv,     setInvalidEnv]        = useState(false);

  useEffect(() => {
    // Kiosk Mode Check: Ngăn chặn chạy trên trình duyệt web thông thường
    // Chỉ cho phép chạy trong môi trường WebView2 của C++ Host
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
          setViolation({
            type:    message.payload?.violationType ?? 'UNKNOWN',
            process: message.payload?.processName   ?? 'Unknown Process',
          });
          break;

        case HostEventType.INTEGRITY_FAIL:
          setIntegrityFail(message.payload?.reason ?? 'Unknown integrity failure');
          break;

        // [DynamicScanner] Kết quả kiểm duyệt từ Ring 3
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
          setScanLog(prev => [scanEvent, ...prev].slice(0, 50)); // Giữ 50 dòng gần nhất

          // Nếu là MALICIOUS thì cũng hiển thị alert chặn
          if (message.payload.verdict === 'MALICIOUS') {
            setViolation({
              type:    'Phần mềm độc hại phát hiện bởi Ring 3',
              process: message.payload.imageName,
            });
          }
          break;
      }
    });

    // Giả lập load driver thành công sau 2s
    const timer = setTimeout(() => setIsDriverLoaded(true), 2000);
    return () => clearTimeout(timer);
  }, []);

  const handleStartExam = () => {
    Bridge.postMessage(ClientCommandType.START_EXAM, { sessionToken: 'EXAM_2026_XYZ' });
    setExamStarted(true);
  };

  // ─── Màn hình Lỗi Môi trường (Chạy trên trình duyệt thường) ──────────────
  if (invalidEnv) {
    return (
      <div className="app-container">
        <div className="alert-overlay animate-fade-in">
          <div className="alert-box" style={{ borderColor: 'rgba(239,68,68,0.4)', background: 'rgba(239,68,68,0.05)' }}>
            <div className="alert-icon" style={{ color: '#ef4444' }}>
              <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
              </svg>
            </div>
            <h2 className="alert-title" style={{ color: '#ef4444' }}>Môi trường Không hợp lệ</h2>
            <p className="subtitle" style={{ color: 'var(--text-main)' }}>
              Không thể truy cập trực tiếp bài thi qua trình duyệt web thông thường.
            </p>
            <div className="status-box" style={{ marginTop: '24px', textAlign: 'left' }}>
              <div className="status-item">
                <span className="status-label">Lý do:</span>
                <span className="status-value status-error">Thiếu Module WebView2 C++ Host</span>
              </div>
              <div className="status-item">
                <span className="status-label">Yêu cầu:</span>
                <span className="status-value">Vui lòng khởi động phần mềm Atch_Kernel_Client.exe</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ─── Màn hình Cảnh báo Vi phạm (Kernel hoặc DynamicScanner) ──────────────
  if (violation) {
    return (
      <div className="app-container">
        <div className="alert-overlay animate-fade-in">
          <div className="alert-box glass-panel">
            <div className="alert-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
                <path d="M12 9v4"/><path d="M12 17h.01"/>
              </svg>
            </div>
            <h2 className="alert-title">Phát hiện Gian lận!</h2>
            <p className="subtitle" style={{ color: 'var(--text-main)' }}>
              Hệ thống đã tự động khóa bài thi và báo cáo hành vi khả nghi.
            </p>
            <div className="status-box" style={{ marginTop: '24px', textAlign: 'left' }}>
              <div className="status-item">
                <span className="status-label">Loại vi phạm:</span>
                <span className="status-value status-error">{violation.type}</span>
              </div>
              <div className="status-item">
                <span className="status-label">Tiến trình:</span>
                <span className="status-value">{violation.process}</span>
              </div>
            </div>
            <button className="primary-btn" onClick={() => window.close()} style={{ marginTop: '16px' }}>
              Thoát Hệ thống
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ─── Màn hình Vi phạm Toàn vẹn (IntegrityChecker phát hiện) ─────────────
  if (integrityFail) {
    return (
      <div className="app-container">
        <div className="alert-overlay animate-fade-in">
          <div className="alert-box" style={{ borderColor: 'rgba(234,179,8,0.4)', background: 'rgba(234,179,8,0.05)', borderRadius: '16px', padding: '32px', width: '420px', textAlign: 'center' }}>
            <div style={{ color: '#eab308', animation: 'pulse 2s infinite' }}>
              <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <h2 style={{ color: '#eab308', fontSize: '22px', margin: '16px 0 12px' }}>Vi phạm Toàn vẹn Hệ thống!</h2>
            <p className="subtitle" style={{ color: 'var(--text-main)' }}>
              Bộ kiểm tra toàn vẹn Ring 3 đã phát hiện hành vi can thiệp vào phần mềm.
            </p>
            <div className="status-box" style={{ marginTop: '24px', textAlign: 'left' }}>
              <div className="status-item">
                <span className="status-label">Chi tiết:</span>
                <span className="status-value" style={{ color: '#eab308', wordBreak: 'break-all', fontSize: '12px' }}>
                  {integrityFail}
                </span>
              </div>
            </div>
            <button className="primary-btn" onClick={() => window.close()} style={{ marginTop: '16px' }}>
              Thoát Hệ thống
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ─── Màn hình Bài thi ─────────────────────────────────────────────────────
  if (examStarted) {
    return (
      <div className="app-container">
        <div className="exam-container animate-fade-in">
          <div className="exam-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{ width: '8px', height: '8px', background: 'var(--success)', borderRadius: '50%', boxShadow: '0 0 8px var(--success)' }}></div>
              <span style={{ fontWeight: 600 }}>Atch_Kernel Secure Browser</span>
              <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                | Ring 3 Scanner: {scanLog.length} sự kiện đã quét
              </span>
            </div>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              {scanLog.some(e => e.verdict === 'SUSPICIOUS') && (
                <span style={{ color: '#eab308', fontSize: '13px', background: 'rgba(234,179,8,0.1)', padding: '4px 10px', borderRadius: '6px' }}>
                  ⚠ {scanLog.filter(e => e.verdict === 'SUSPICIOUS').length} tiến trình đáng ngờ
                </span>
              )}
              <button style={{ background: 'transparent', color: 'var(--text-muted)' }} onClick={() => setExamStarted(false)}>
                Thoát
              </button>
            </div>
          </div>

          {/* Log quét DynamicScanner - hiển thị dạng sidebar */}
          {scanLog.length > 0 && (
            <div style={{
              position: 'fixed', bottom: '16px', right: '16px',
              width: '360px', maxHeight: '260px', overflowY: 'auto',
              background: 'rgba(15,23,42,0.95)', border: '1px solid var(--glass-border)',
              borderRadius: '12px', padding: '12px', zIndex: 50
            }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px', fontWeight: 600 }}>
                🔍 RING 3 SCANNER LOG
              </div>
              {scanLog.slice(0, 8).map((ev, idx) => (
                <div key={idx} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)',
                  fontSize: '12px'
                }}>
                  <span style={{ color: ev.verdict === 'TRUSTED' ? 'var(--success)' : ev.verdict === 'MALICIOUS' ? 'var(--danger)' : '#eab308' }}>
                    {ev.verdict === 'TRUSTED' ? '✓' : ev.verdict === 'MALICIOUS' ? '✗' : '?'} {ev.imageName}
                  </span>
                  <span style={{ color: 'var(--text-muted)', fontSize: '10px' }}>{ev.timestamp}</span>
                </div>
              ))}
            </div>
          )}

          <div style={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center', color: 'var(--text-muted)' }}>
            <h2>Nội dung bài thi sẽ hiển thị ở đây</h2>
          </div>
        </div>
      </div>
    );
  }

  // ─── Màn hình Khởi động ───────────────────────────────────────────────────
  return (
    <div className="app-container">
      <div className="lock-screen glass-panel animate-fade-in">
        <div className="lock-icon-wrapper">
          <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <div>
          <h1 className="title">Atch_Kernel</h1>
          <p className="subtitle">Hệ thống Giám sát Thi cử An toàn cấp độ Kernel</p>
        </div>
        <div className="status-box">
          <div className="status-item">
            <span className="status-label">Trạng thái Ring 3</span>
            <span className="status-value status-ok">Sẵn sàng</span>
          </div>
          <div className="status-item">
            <span className="status-label">Kết nối Ring 0 (Driver)</span>
            <span className={`status-value ${isDriverLoaded ? 'status-ok' : 'status-wait'}`}>
              {isDriverLoaded ? 'Đã kết nối' : 'Đang khởi tạo...'}
            </span>
          </div>
          <div className="status-item">
            <span className="status-label">Bộ quét động (DynamicScanner)</span>
            <span className={`status-value ${isDriverLoaded ? 'status-ok' : 'status-wait'}`}>
              {isDriverLoaded ? 'Hoạt động' : 'Chờ Driver...'}
            </span>
          </div>
          <div className="status-item">
            <span className="status-label">Kiểm tra Toàn vẹn Ring 3</span>
            <span className="status-value status-ok">Hoạt động</span>
          </div>
        </div>
        <button className="primary-btn" disabled={!isDriverLoaded} onClick={handleStartExam}>
          {isDriverLoaded ? 'Bắt đầu Bài thi' : 'Vui lòng chờ...'}
        </button>
      </div>
    </div>
  );
}

export default App;
