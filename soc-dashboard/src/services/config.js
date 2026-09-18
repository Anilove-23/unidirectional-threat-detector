// Accept both the backend origin used by older .env files and an explicit /api.
const configuredBase = (import.meta.env.VITE_API_URL || '/api').replace(/\/+$/, '');
export const API_BASE = configuredBase.endsWith('/api') ? configuredBase : `${configuredBase}/api`;
