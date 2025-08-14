# Cyber Range Logging System

This document describes the comprehensive logging system implemented in the Cyber Range application.

## Overview

The logging system captures all types of application events including:
- API requests and responses
- Authentication events
- Security events
- Lab operations
- VM operations
- Database operations
- User operations
- System events
- Errors and exceptions

## Log Files

All logs are stored in the `logs/` directory with daily rotation. The following log files are generated:

### Core Log Files
- `application-YYYY-MM-DD.log` - All application logs (debug level and above)
- `error-YYYY-MM-DD.log` - Error logs only
- `info-YYYY-MM-DD.log` - Info level and above
- `warning-YYYY-MM-DD.log` - Warning level and above

### Specialized Log Files
- `access-YYYY-MM-DD.log` - HTTP request/response logs
- `auth-YYYY-MM-DD.log` - Authentication events
- `security-YYYY-MM-DD.log` - Security-related events
- `vm-operations-YYYY-MM-DD.log` - Virtual machine operations
- `database-YYYY-MM-DD.log` - Database operations
- `lab-operations-YYYY-MM-DD.log` - Lab management operations

## Log Format

Each log entry includes:
```
YYYY-MM-DD HH:mm:ss [LEVEL]: Message
Metadata: {
  "category": "CATEGORY_NAME",
  "additionalData": "..."
}
```

## Log Levels

- **ERROR** - Application errors, exceptions
- **WARN** - Warning conditions, security events
- **INFO** - General information, successful operations
- **DEBUG** - Detailed debugging information

## Log Categories

- **ACCESS** - HTTP requests and responses
- **AUTH** - Authentication and authorization
- **SECURITY** - Security events and violations
- **VM_OPERATIONS** - Virtual machine lifecycle
- **LAB_OPERATIONS** - Lab management
- **USER_OPERATIONS** - User management
- **DATABASE** - Database operations
- **SYSTEM** - System-level events
- **ERROR** - Application errors

## Using the Logging System

### In Code

```javascript
const loggers = require('./config/logger');

// Basic logging
loggers.auth.info('User login successful', { userId: 123, ip: '192.168.1.1' });
loggers.security.warn('Failed login attempt', { username: 'admin', ip: '192.168.1.1' });
loggers.error.error('Database connection failed', { error: error.message });

// Specialized logging functions
loggers.logAuth('LOGIN_SUCCESS', userId, { ip: req.ip });
loggers.logSecurity('INVALID_LOGIN_ATTEMPT', { username, ip: req.ip });
loggers.logVM('START', labId, { vmId, templateId });
loggers.logLab('CREATE', labId, userId, { name, category });
loggers.logError(error, req, { operation: 'USER_CREATION' });
```

### Log Management Scripts

#### Log Viewer (`scripts/log-viewer.js`)

View and monitor logs in real-time:

```bash
# List all available log files
npm run logs:list

# Show recent errors
npm run logs:errors

# Show recent security events
npm run logs:security

# Show recent authentication events
npm run logs:auth

# Show recent access logs
npm run logs:access

# Tail a specific log file (last 50 lines)
node scripts/log-viewer.js tail application-2024-01-15.log

# Follow a log file in real-time
node scripts/log-viewer.js follow error-2024-01-15.log

# Follow with custom lines
node scripts/log-viewer.js tail application-2024-01-15.log 100
```

#### Log Cleanup (`scripts/log-cleanup.js`)

Manage log file size and retention:

```bash
# Show log statistics
npm run logs:stats

# Preview what would be cleaned (dry run)
npm run logs:clean

# Clean old logs (default: 30+ days)
node scripts/log-cleanup.js clean

# Clean logs older than 7 days
node scripts/log-cleanup.js clean 7

# Truncate large files (default: 100MB+)
node scripts/log-cleanup.js truncate

# Truncate files larger than 50MB
node scripts/log-cleanup.js truncate 50

# Full cleanup (old files + large files)
node scripts/log-cleanup.js full

# Dry run for any operation
node scripts/log-cleanup.js clean --dry-run
node scripts/log-cleanup.js truncate --dry-run
node scripts/log-cleanup.js full --dry-run
```

## Configuration

Log configuration is in `config/logger.js`:

- **Log Level**: Set via `LOG_LEVEL` environment variable (default: 'info')
- **File Rotation**: Daily rotation with compression
- **Retention**: 14 days by default
- **Max File Size**: 20MB per file before rotation
- **Console Output**: Enabled in development mode

## Environment Variables

```bash
# Set log level (error, warn, info, debug)
LOG_LEVEL=debug

# Environment (affects console output)
NODE_ENV=production
```

## Automated Log Cleanup

Consider setting up automated log cleanup via cron:

```bash
# Add to crontab (daily cleanup at 2 AM)
0 2 * * * cd /path/to/backend && node scripts/log-cleanup.js full

# Weekly statistics report
0 9 * * 1 cd /path/to/backend && node scripts/log-cleanup.js stats
```

## Security Considerations

1. **Log Sanitization**: Sensitive data (passwords, tokens) are never logged
2. **Access Control**: Log files should have restricted access permissions
3. **Retention Policy**: Implement appropriate log retention based on compliance requirements
4. **Monitoring**: Monitor disk space usage due to log accumulation

## Performance Impact

- **Async Logging**: All logging operations are asynchronous
- **File Rotation**: Automatic rotation prevents individual files from becoming too large
- **Selective Logging**: Different log levels allow filtering in production

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure the application has write permissions to the `logs/` directory
2. **Disk Space**: Monitor available disk space, especially in high-traffic scenarios
3. **Log Rotation**: Check that old logs are being properly compressed and removed

### Log Analysis

Use the built-in log viewer or standard Unix tools:

```bash
# Search for specific patterns
grep "ERROR" logs/application-2024-01-15.log

# Count events by type
grep -c "LOGIN_SUCCESS" logs/auth-2024-01-15.log

# Monitor in real-time
tail -f logs/application-$(date +%Y-%m-%d).log

# Analyze access patterns
awk '{print $1, $4}' logs/access-2024-01-15.log | sort | uniq -c
```

## Best Practices

1. **Structured Logging**: Use consistent metadata formats
2. **Appropriate Levels**: Use correct log levels for different types of events
3. **Context**: Include relevant context (user ID, IP, operation)
4. **Performance**: Avoid excessive logging in high-frequency operations
5. **Security**: Never log sensitive information
6. **Monitoring**: Regularly monitor log files for security events and errors

## Log Monitoring and Alerting

Consider implementing monitoring for:
- High error rates
- Security events (failed logins, unauthorized access attempts)
- System performance issues
- Unusual patterns in access logs

Example monitoring queries:
```bash
# Failed login attempts in last hour
grep "LOGIN_FAILED" logs/auth-$(date +%Y-%m-%d).log | grep "$(date +%Y-%m-%d\ %H):"

# Error rate in last 24 hours
grep "ERROR" logs/error-$(date +%Y-%m-%d).log | wc -l
```
