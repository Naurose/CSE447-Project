// Role-based access control middleware

// requireRole(...roles) — Express middleware that checks req.user.role
// Wraps route handlers: router.get('/premium-games', requireRole('premium', 'admin'), handler)