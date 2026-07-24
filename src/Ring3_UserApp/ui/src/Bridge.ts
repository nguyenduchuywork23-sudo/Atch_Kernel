// Bridge.ts
// Giao tiếp giữa React và C++ WebView2 Host

// Khai báo type cho window.chrome.webview
declare global {
  interface Window {
    chrome: {
      webview?: {
        postMessage: (message: any) => void;
        addEventListener: (type: string, listener: (event: any) => void) => void;
        removeEventListener: (type: string, listener: (event: any) => void) => void;
      };
    };
  }
}

// Các loại Event từ C++ Host gửi sang React (Nhận)
export enum HostEventType {
  HEARTBEAT_ACK       = 'HEARTBEAT_ACK',
  VIOLATION_DETECTED  = 'VIOLATION_DETECTED',
  DRIVER_INITIALIZED  = 'DRIVER_INITIALIZED',
  DRIVER_LOST         = 'DRIVER_LOST',
  INTEGRITY_FAIL      = 'INTEGRITY_FAIL',
  // [DynamicScanner] Kết quả kiểm duyệt file/tiến trình ở Ring 3
  SCAN_RESULT         = 'SCAN_RESULT',
}

// Các loại Command từ React gửi sang C++ Host (Gửi)
export enum ClientCommandType {
  START_EXAM = 'START_EXAM',
  END_EXAM = 'END_EXAM',
  REQUEST_UNLOCK = 'REQUEST_UNLOCK',
}

interface MessageData {
  type: string;
  payload?: any;
}

export class Bridge {
  static postMessage(type: ClientCommandType, payload?: any) {
    const message: MessageData = { type, payload };
    
    if (window.chrome?.webview) {
      // Đang chạy trong WebView2 (C++ Host)
      window.chrome.webview.postMessage(message);
    } else {
      // Đang chạy trên trình duyệt thường (Dev/Test)
      console.log('[Mock WebView2] Sending message to Host:', message);
      
      // Giả lập phản hồi từ Host cho mục đích test
      if (type === ClientCommandType.START_EXAM) {
        setTimeout(() => {
          this.mockReceiveMessage({
            type: HostEventType.DRIVER_INITIALIZED,
            payload: { success: true }
          });
        }, 1000);
      }
    }
  }

  static addListener(callback: (message: MessageData) => void) {
    if (window.chrome?.webview) {
      window.chrome.webview.addEventListener('message', (event: any) => {
        try {
          // WebView2 truyền data dưới dạng event.data
          const data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
          callback(data);
        } catch (e) {
          console.error('Failed to parse message from host:', e);
        }
      });
    } else {
      // Dùng window event thông thường cho test
      window.addEventListener('message', (event) => {
        if (event.data && event.data.__mockHostMessage) {
          callback(event.data.payload);
        }
      });
    }
  }

  // Hàm helper để giả lập nhận tin nhắn khi test trên browser
  static mockReceiveMessage(message: MessageData) {
    window.postMessage({
      __mockHostMessage: true,
      payload: message
    }, '*');
  }
}
