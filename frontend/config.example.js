// Plantilla de configuración del frontend (SÍ se versiona).
// Copia este archivo como config.js y completa tus valores reales.
// config.js está en .gitignore para no publicar la URL/secreto de tu despliegue.

// URL base de la API (output ScanApiUrl del stack SAM).
export const API_BASE_URL = 'https://TU-API-ID.execute-api.us-east-1.amazonaws.com';

// Secreto compartido para el header x-api-key.
// Debe coincidir con el parámetro ApiSharedSecret del despliegue.
// Déjalo vacío si la API tiene la autenticación deshabilitada.
export const API_KEY = '';
