const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');
require('dotenv').config();
const { connectDB } = require('./config/db');
const { initializeAdmin } = require('./controllers/authController');
const loggers = require('./config/logger');
const scoringService = require('./services/scoringService');
const gameEngine = require('./services/gameEngine');

// Import models to ensure associations are set up
require('./models');

// Import routes
const authRoutes = require('./routes/auth');
const labRoutes = require('./routes/labs');
const vmRoutes = require('./routes/vms');
const statusRoutes = require('./routes/status');
const flagRoutes = require('./routes/flags');
const webLabRoutes = require('./routes/webLabRoutes');
const matchRoutes = require('./routes/matches');
const teamRoutes = require('./routes/teams');
const analyticsRoutes = require('./routes/analytics');
const cyberwarAdminRoutes = require('./routes/cyberwarAdmin');
const proxmoxRoutes = require('./routes/proxmox');

// Create Express app
const app = express();
const server = http.createServer(app);

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:5000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-auth-token']
}));
app.use(express.json());

// Add request logging middleware
app.use(loggers.logRequest);

// Serve static files from the examples directory
app.use(express.static(path.join(__dirname, 'examples')));

// Middleware to set Lab-Status header for completed labs
app.use((req, res, next) => {
  // Check if the request has a cookie indicating lab completion
  if (req.headers.cookie && req.headers.cookie.includes('Lab-Status=Completed')) {
    res.set('Lab-Status', 'Completed');
  }
  next();
});
// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/labs', labRoutes);
app.use('/api/vms', vmRoutes);
app.use('/api/status', statusRoutes);
app.use('/api/flags', flagRoutes);
app.use('/api/weblabs', webLabRoutes);
app.use('/api/matches', matchRoutes);
app.use('/api/teams', teamRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/admin/cyberwar', cyberwarAdminRoutes);
app.use('/api/proxmox', proxmoxRoutes);

// Connect to MySQL and initialize services
connectDB()
  .then(() => {
    loggers.system.info('Database connected successfully');
    console.log('✅ MySQL connected');
    // Initialize admin user
    return initializeAdmin();
  })
  .then(() => {
    loggers.system.info('Admin user initialization completed');
    console.log('✅ Admin user initialized');
    
    // Initialize WebSocket server for real-time scoring
    try {
      scoringService.initializeWebSocket(server);
      console.log('✅ WebSocket server initialized for real-time scoring');
      loggers.system.info('WebSocket server initialized');
    } catch (wsError) {
      console.warn('⚠️  WebSocket initialization failed:', wsError.message);
      loggers.system.warn('WebSocket initialization failed', { error: wsError.message });
    }
    
    // Initialize Game Engine
    return gameEngine.initialize().catch(gameEngineError => {
      console.warn('⚠️  Game Engine initialization failed (will continue without VM management):', gameEngineError.message);
      loggers.system.warn('Game Engine initialization failed', { error: gameEngineError.message });
    });
  })
  .then(() => {
    console.log('✅ Game Engine initialized (or skipped)');
  })
  .catch(err => {
    loggers.system.error('Service initialization error', { error: err.message, stack: err.stack });
    console.error('❌ Service initialization error:', err);
  });

// Error handling middleware
app.use((err, req, res, next) => {
  loggers.logError(err, req);
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Add health check with services status
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    services: {
      database: 'connected',
      gameEngine: gameEngine ? 'initialized' : 'not_initialized',
      scoringService: scoringService ? 'available' : 'unavailable',
      websocket: scoringService.wss ? 'active' : 'inactive'
    },
    features: {
      cyberwarsMatches: true,
      realTimeScoring: !!scoringService.wss,
      teamManagement: true,
      packetAnalysis: true,
      airgappedDeployment: true
    }
  });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  loggers.system.info(`CyberRange server started successfully on port ${PORT}`, { 
    port: PORT, 
    environment: process.env.NODE_ENV,
    features: ['labs', 'matches', 'teams', 'scoring', 'websockets']
  });
  console.log(`🚀 CyberRange Backend Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 API Base URL: http://localhost:${PORT}/api`);
  console.log(`🌐 WebSocket Endpoint: ws://localhost:${PORT}/ws/scoring`);
  console.log(`⚡ Features: Labs, Cyber-warfare matches, Real-time scoring, Team competition`);
  
  if (process.env.NODE_ENV === 'development') {
    console.log('\n📖 API Documentation:');
    console.log('   GET  /api/matches - List matches');
    console.log('   POST /api/matches - Create match (admin)');
    console.log('   GET  /api/teams - List teams');
    console.log('   POST /api/teams - Create team');
    console.log('   GET  /api/labs - List labs');
    console.log('   GET  /api/health - Health check');
  }
});

// Graceful shutdown handling
process.on('SIGTERM', async () => {
  console.log('\n🛑 SIGTERM received. Shutting down gracefully...');
  
  try {
    // Close WebSocket connections
    if (scoringService.wss) {
      scoringService.wss.close();
      console.log('✅ WebSocket server closed.');
    }
    
    // Close HTTP server
    server.close(() => {
      console.log('✅ HTTP server closed.');
      loggers.system.info('Server shutdown completed');
      process.exit(0);
    });
  } catch (error) {
    console.error('❌ Error during graceful shutdown:', error);
    loggers.system.error('Graceful shutdown error', { error: error.message });
    process.exit(1);
  }
});

process.on('SIGINT', async () => {
  console.log('\n🛑 SIGINT received (Ctrl+C). Shutting down gracefully...');
  process.emit('SIGTERM');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  loggers.system.error('Unhandled promise rejection', { reason, promise });
  // Don't exit the process in production, just log the error
  if (process.env.NODE_ENV === 'development') {
    process.exit(1);
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  loggers.system.error('Uncaught exception', { error: error.message, stack: error.stack });
  process.exit(1);
});
