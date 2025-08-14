const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');

// Create logs directory if it doesn't exist
const fs = require('fs');
const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format for logs
const customFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ level, message, timestamp, stack, ...metadata }) => {
    let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;
    
    // Add stack trace if available
    if (stack) {
      log += `\n${stack}`;
    }
    
    // Add metadata if present
    if (Object.keys(metadata).length > 0) {
      log += `\nMetadata: ${JSON.stringify(metadata, null, 2)}`;
    }
    
    return log;
  })
);

// Create different transports for different log levels
const createRotateTransport = (filename, level = 'info', maxSize = '20m', maxFiles = '14d') => {
  return new DailyRotateFile({
    filename: path.join(logsDir, filename),
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize,
    maxFiles,
    level,
    format: customFormat
  });
};

// Configure logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: customFormat,
  defaultMeta: { service: 'cyber-range-backend' },
  transports: [
    // All logs
    createRotateTransport('application-%DATE%.log', 'debug'),
    
    // Error logs only
    createRotateTransport('error-%DATE%.log', 'error'),
    
    // Info and above
    createRotateTransport('info-%DATE%.log', 'info'),
    
    // Warning and above
    createRotateTransport('warning-%DATE%.log', 'warn'),
    
    // Security-related logs
    createRotateTransport('security-%DATE%.log', 'info'),
    
    // API access logs
    createRotateTransport('access-%DATE%.log', 'info'),
    
    // Database logs
    createRotateTransport('database-%DATE%.log', 'debug'),
    
    // VM operations logs
    createRotateTransport('vm-operations-%DATE%.log', 'info'),
    
    // Authentication logs
    createRotateTransport('auth-%DATE%.log', 'info')
  ]
});

// Add console output for development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// Create specialized loggers for different components
const createSpecializedLogger = (category) => {
  return {
    info: (message, metadata = {}) => logger.info(message, { category, ...metadata }),
    warn: (message, metadata = {}) => logger.warn(message, { category, ...metadata }),
    error: (message, metadata = {}) => logger.error(message, { category, ...metadata }),
    debug: (message, metadata = {}) => logger.debug(message, { category, ...metadata })
  };
};

// Export specialized loggers
const loggers = {
  main: logger,
  
  // API access logger
  access: createSpecializedLogger('ACCESS'),
  
  // Authentication logger
  auth: createSpecializedLogger('AUTH'),
  
  // Database logger
  database: createSpecializedLogger('DATABASE'),
  
  // VM operations logger
  vm: createSpecializedLogger('VM_OPERATIONS'),
  
  // Security logger
  security: createSpecializedLogger('SECURITY'),
  
  // Lab operations logger
  lab: createSpecializedLogger('LAB_OPERATIONS'),
  
  // User operations logger
  user: createSpecializedLogger('USER_OPERATIONS'),
  
  // System logger
  system: createSpecializedLogger('SYSTEM'),
  
  // Error logger
  error: createSpecializedLogger('ERROR')
};

// Helper function to log HTTP requests
loggers.logRequest = (req, res, next) => {
  const start = Date.now();
  
  // Log request details
  loggers.access.info('Incoming Request', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    userRole: req.user?.role
  });
  
  // Log response when finished
  res.on('finish', () => {
    const duration = Date.now() - start;
    loggers.access.info('Response Sent', {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      userId: req.user?.id
    });
  });
  
  next();
};

// Helper function to log errors
loggers.logError = (error, req = null, additional = {}) => {
  const errorInfo = {
    message: error.message,
    stack: error.stack,
    name: error.name,
    ...additional
  };
  
  if (req) {
    errorInfo.request = {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      body: req.body
    };
  }
  
  loggers.error.error('Application Error', errorInfo);
};

// Helper function to log security events
loggers.logSecurity = (event, details = {}) => {
  loggers.security.warn(`Security Event: ${event}`, details);
};

// Helper function to log authentication events
loggers.logAuth = (event, userId, details = {}) => {
  loggers.auth.info(`Auth Event: ${event}`, {
    userId,
    ...details
  });
};

// Helper function to log VM operations
loggers.logVM = (operation, labId, details = {}) => {
  loggers.vm.info(`VM Operation: ${operation}`, {
    labId,
    ...details
  });
};

// Helper function to log lab operations
loggers.logLab = (operation, labId, userId, details = {}) => {
  loggers.lab.info(`Lab Operation: ${operation}`, {
    labId,
    userId,
    ...details
  });
};

// Helper function to log user operations
loggers.logUser = (operation, userId, targetUserId = null, details = {}) => {
  loggers.user.info(`User Operation: ${operation}`, {
    userId,
    targetUserId,
    ...details
  });
};

// Helper function to log database operations
loggers.logDatabase = (operation, table, details = {}) => {
  loggers.database.debug(`Database Operation: ${operation}`, {
    table,
    ...details
  });
};

module.exports = loggers;
