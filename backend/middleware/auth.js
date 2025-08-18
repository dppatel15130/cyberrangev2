const jwt = require('jsonwebtoken');

// Middleware to verify JWT token
exports.auth = (req, res, next) => {
  console.log('=== AUTH MIDDLEWARE ===');
  console.log('Request headers:', JSON.stringify(req.headers, null, 2));
  
  // Get token from headers
  let token = req.header('x-auth-token');
  
  // If token not found in x-auth-token, check Authorization header
  if (!token && req.header('Authorization')) {
    const authHeader = req.header('Authorization');
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else {
      token = authHeader;
    }
  }
  
  console.log('Token from headers:', token ? '[TOKEN_PRESENT]' : 'MISSING');

  // Check if no token
  if (!token) {
    console.error('No token provided in x-auth-token or Authorization header');
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    console.log('Verifying JWT token...');
    console.log('Token to verify:', token.substring(0, 20) + '...');
    console.log('JWT_SECRET present:', !!process.env.JWT_SECRET);
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    console.log('Token verified successfully. Decoded payload:', {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
      iat: decoded.iat ? new Date(decoded.iat * 1000).toISOString() : 'N/A',
      exp: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : 'N/A',
      allClaims: Object.keys(decoded)
    });

    // Ensure the role is set correctly
    if (!decoded.role) {
      console.warn('No role found in JWT token, defaulting to "user"');
      decoded.role = 'user';
    }
    
    // Add user from payload to request
    req.user = decoded;
    console.log('Request user set to:', JSON.stringify(req.user, null, 2));
    next();
  } catch (error) {
    console.error('Token verification failed:', {
      name: error.name,
      message: error.message,
      expiredAt: error.expiredAt ? new Date(error.expiredAt).toISOString() : 'N/A'
    });
    res.status(401).json({ 
      message: 'Token is not valid',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Middleware to check if user is admin or cyberwar_admin
exports.admin = (req, res, next) => {
  console.log('\n=== ADMIN MIDDLEWARE ===');
  console.log('Request URL:', req.originalUrl);
  console.log('Request method:', req.method);
  console.log('User object:', JSON.stringify({
    id: req.user?.id,
    email: req.user?.email,
    role: req.user?.role || 'none',
    hasRole: !!req.user?.role
  }, null, 2));
  
  if (!req.user) {
    console.error('Access denied: No user object found in request');
    return res.status(401).json({ 
      message: 'Authentication required',
      error: 'No user session found',
      timestamp: new Date().toISOString()
    });
  }
  
  const validRoles = ['admin', 'cyberwar_admin'];
  const hasValidRole = validRoles.includes(req.user.role);
  
  if (!hasValidRole) {
    console.error('Access denied: Invalid role', {
      currentRole: req.user.role,
      allowedRoles: validRoles,
      path: req.path,
      method: req.method
    });
    return res.status(403).json({ 
      message: 'Access denied, admin privileges required',
      error: 'Insufficient permissions',
      currentRole: req.user.role,
      allowedRoles: validRoles,
      timestamp: new Date().toISOString()
    });
  }
  
  console.log('Access granted to role:', req.user.role);
  next();
};

// Middleware to check if user is red team
exports.redTeam = (req, res, next) => {
  if (req.user.role !== 'red_team' && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied, red team privileges required' });
  }
  next();
};

// Middleware to check if user is blue team
exports.blueTeam = (req, res, next) => {
  if (req.user.role !== 'blue_team' && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied, blue team privileges required' });
  }
  next();
};