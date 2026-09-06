// Centralized JWT auth middleware

// JWT verification middleware (currently inline in some routes, needs to be centralized)
// Extracts req.user from token, including role
// Blocks requests with expired/invalid tokens