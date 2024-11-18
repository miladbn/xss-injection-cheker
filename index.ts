const sanitizeInput = (input: unknown): unknown => {
  if (typeof input === "string") {
    // Remove potential XSS vectors
    return input
      .replace(/[<>]/g, "") // Remove < and >
      .replace(/javascript:/gi, "") // Remove javascript: protocol
      .replace(/data:/gi, "") // Remove data: protocol
      .trim();
  }
  if (Array.isArray(input)) {
    return input.map(sanitizeInput);
  }
  if (typeof input === "object" && input !== null) {
    return Object.fromEntries(
      Object.entries(input).map(([key, value]) => [key, sanitizeInput(value)])
    );
  }
  return input;
};

const rateLimitConfig = {
  maxRequests: 100,
  perWindow: 60000, // 1 minute
  requests: new Map<string, number[]>(),
};

// Security: Rate limiting check
const checkRateLimit = (endpoint: string): boolean => {
  const now = Date.now();
  const requests = rateLimitConfig.requests.get(endpoint) || [];

  // Remove old requests
  const validRequests = requests.filter(
    (time) => now - time < rateLimitConfig.perWindow
  );

  if (validRequests.length >= rateLimitConfig.maxRequests) {
    return false;
  }

  validRequests.push(now);
  rateLimitConfig.requests.set(endpoint, validRequests);
  return true;
};

const instance = axios.create({
  baseURL: BASE_URL,
  timeout: REQUEST_TIMEOUT,
  headers: {
    Authorization: `Bearer ${Cookies.get("Authorization")}`,
    username: `${Cookies.get("sub")}`,
    password: `${Cookies.get("sub")}`,
    apiKey: API_KEY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
  },
});

instance.interceptors.request.use(
  (config) => {
    // Security: Check rate limiting
    const endpoint = config.url || "";
    if (!checkRateLimit(endpoint)) {
      throw new Error("Rate limit exceeded");
    }

    // Security: Sanitize request data
    if (config.params) {
      config.params = sanitizeInput(config.params);
    }
    if (config.data) {
      config.data = sanitizeInput(config.data);
    }

    return config;
  },
  (error) => Promise.reject(error)
);
