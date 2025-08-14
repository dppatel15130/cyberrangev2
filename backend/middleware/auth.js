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
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Token verified successfully. User:', {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role,
      iat: decoded.iat ? new Date(decoded.iat * 1000).toISOString() : 'N/A',
      exp: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : 'N/A'
    });

    // Add user from payload to request
    req.user = decoded;
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

// Middleware to check if user is admin
exports.admin = (req, res, next) => {
  console.log('=== ADMIN MIDDLEWARE ===');
  console.log('User role:', req.user?.role || 'undefined');
  
  if (req.user?.role !== 'admin') {
    console.error('Access denied: User is not an admin');
    return res.status(403).json({ 
      message: 'Access denied, admin privileges required',
      currentRole: req.user?.role || 'none'
    });
  }
  console.log('User has admin privileges');
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