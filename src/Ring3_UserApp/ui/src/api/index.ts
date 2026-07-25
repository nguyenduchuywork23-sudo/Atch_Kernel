const API_BASE_URL = 'http://localhost:8080/api';

const getAuthHeaders = () => {
  const token = sessionStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {})
  };
};

const fetchAuth = async (url: string, options: RequestInit = {}) => {
  const response = await fetch(url, options);
  if (response.status === 401 || response.status === 403) {
    sessionStorage.removeItem('token');
  }
  return response;
};

export const login = async (credentials: any) => {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(credentials),
  });
  
  if (!response.ok) {
    throw new Error('Login failed');
  }
  
  return response.json();
};

export const getExam = async (examId: string) => {
  const response = await fetchAuth(`${API_BASE_URL}/exams/${examId}`, { headers: getAuthHeaders() });
  
  if (!response.ok) {
    throw new Error('Failed to fetch exam');
  }
  
  return response.json();
};

export const submitExam = async (examId: string, answers: any) => {
  const response = await fetchAuth(`${API_BASE_URL}/exams/${examId}/submit`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(answers),
  });
  
  if (!response.ok) {
    throw new Error('Failed to submit exam');
  }
  
  return response.json();
};

export const getSessions = async (signal?: AbortSignal) => {
  const response = await fetchAuth(`${API_BASE_URL}/teacher/students/search?query=`, { headers: getAuthHeaders(), signal });
  if (!response.ok) throw new Error('Failed to fetch sessions');
  const data = await response.json();
  return data.map((u: any) => ({
    studentName: u.username,
    studentId: u.id,
    status: 'ACTIVE'
  }));
};

export const getLogs = async (signal?: AbortSignal) => {
  const response = await fetchAuth(`${API_BASE_URL}/teacher/logs/1`, { headers: getAuthHeaders(), signal });
  if (!response.ok) throw new Error('Failed to fetch logs');
  const data = await response.json();
  return data.map((log: any) => ({
    verdict: log.action === 'VIOLATION' || log.action === 'VIOLATION_DETECTED' ? 'MALICIOUS' : 'TRUSTED',
    process: log.details || log.action,
    timestamp: log.timestamp
  }));
};

export const getUsers = async () => {
  const response = await fetchAuth(`${API_BASE_URL}/admin/users`, { headers: getAuthHeaders() });
  if (!response.ok) throw new Error('Failed to fetch users');
  return response.json();
};

export const getConfig = async () => {
  const response = await fetchAuth(`${API_BASE_URL}/config`, { headers: getAuthHeaders() });
  if (!response.ok) throw new Error('Failed to fetch config');
  return response.json();
};

export const saveConfig = async (key: string, value: string) => {
  const response = await fetchAuth(`${API_BASE_URL}/admin/config`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ key, value }),
  });
  if (!response.ok) throw new Error('Failed to save config');
  return response;
};

export const unlockExam = async () => {
  const response = await fetchAuth(`${API_BASE_URL}/teacher/unlock`, {
    method: 'POST',
    headers: getAuthHeaders()
  });
  if (!response.ok) throw new Error('Failed to unlock exam');
  return response;
};

export const postSecurityLog = async (eventType: string, data: any) => {
  const response = await fetchAuth(`${API_BASE_URL}/security-logs`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ eventType, data }),
  });
  if (!response.ok) throw new Error('Failed to post security log');
  return response;
};
