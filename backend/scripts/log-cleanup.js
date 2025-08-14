#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const logsDir = path.join(__dirname, '../logs');

// Configuration
const DEFAULT_RETENTION_DAYS = 30;
const DEFAULT_MAX_SIZE_MB = 100;

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  bright: '\x1b[1m'
};

// Function to format file size
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Function to get file age in days
function getFileAgeDays(filePath) {
  const stat = fs.statSync(filePath);
  const now = new Date();
  const fileDate = new Date(stat.mtime);
  const diffTime = Math.abs(now - fileDate);
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  return diffDays;
}

// Function to clean old log files
function cleanOldLogs(retentionDays = DEFAULT_RETENTION_DAYS, dryRun = false) {
  if (!fs.existsSync(logsDir)) {
    console.log(`${colors.red}Logs directory not found: ${logsDir}${colors.reset}`);
    return;
  }

  const files = fs.readdirSync(logsDir)
    .filter(file => file.endsWith('.log'))
    .map(file => {
      const filePath = path.join(logsDir, file);
      const stat = fs.statSync(filePath);
      const age = getFileAgeDays(filePath);
      return {
        name: file,
        path: filePath,
        size: stat.size,
        age: age,
        modified: stat.mtime
      };
    });

  const oldFiles = files.filter(file => file.age > retentionDays);
  
  if (oldFiles.length === 0) {
    console.log(`${colors.green}No log files older than ${retentionDays} days found.${colors.reset}`);
    return;
  }

  console.log(`${colors.bright}${colors.blue}Files older than ${retentionDays} days:${colors.reset}\n`);
  
  let totalSize = 0;
  oldFiles.forEach(file => {
    totalSize += file.size;
    const sizeStr = formatFileSize(file.size);
    const modifiedStr = file.modified.toLocaleDateString();
    console.log(`${colors.yellow}${file.name}${colors.reset} (${sizeStr}, ${file.age} days old, modified: ${modifiedStr})`);
  });

  console.log(`\n${colors.bright}Total size to be cleaned: ${formatFileSize(totalSize)}${colors.reset}`);

  if (dryRun) {
    console.log(`${colors.blue}\n[DRY RUN] Would delete ${oldFiles.length} files${colors.reset}`);
    return;
  }

  // Delete old files
  let deletedCount = 0;
  let deletedSize = 0;
  
  oldFiles.forEach(file => {
    try {
      fs.unlinkSync(file.path);
      deletedCount++;
      deletedSize += file.size;
      console.log(`${colors.green}Deleted: ${file.name}${colors.reset}`);
    } catch (error) {
      console.log(`${colors.red}Error deleting ${file.name}: ${error.message}${colors.reset}`);
    }
  });

  console.log(`\n${colors.bright}${colors.green}Cleanup completed:${colors.reset}`);
  console.log(`Files deleted: ${deletedCount}`);
  console.log(`Space freed: ${formatFileSize(deletedSize)}`);
}

// Function to clean large log files
function cleanLargeFiles(maxSizeMB = DEFAULT_MAX_SIZE_MB, dryRun = false) {
  if (!fs.existsSync(logsDir)) {
    console.log(`${colors.red}Logs directory not found: ${logsDir}${colors.reset}`);
    return;
  }

  const maxSizeBytes = maxSizeMB * 1024 * 1024;
  
  const files = fs.readdirSync(logsDir)
    .filter(file => file.endsWith('.log'))
    .map(file => {
      const filePath = path.join(logsDir, file);
      const stat = fs.statSync(filePath);
      return {
        name: file,
        path: filePath,
        size: stat.size,
        modified: stat.mtime
      };
    });

  const largeFiles = files.filter(file => file.size > maxSizeBytes);
  
  if (largeFiles.length === 0) {
    console.log(`${colors.green}No log files larger than ${maxSizeMB}MB found.${colors.reset}`);
    return;
  }

  console.log(`${colors.bright}${colors.blue}Files larger than ${maxSizeMB}MB:${colors.reset}\n`);
  
  largeFiles.forEach(file => {
    const sizeStr = formatFileSize(file.size);
    const modifiedStr = file.modified.toLocaleDateString();
    console.log(`${colors.yellow}${file.name}${colors.reset} (${sizeStr}, modified: ${modifiedStr})`);
  });

  if (dryRun) {
    console.log(`${colors.blue}\n[DRY RUN] Would truncate ${largeFiles.length} files${colors.reset}`);
    return;
  }

  // Truncate large files (keep last 1000 lines)
  let processedCount = 0;
  
  largeFiles.forEach(file => {
    try {
      const content = fs.readFileSync(file.path, 'utf8');
      const lines = content.split('\n');
      const keepLines = 1000;
      
      if (lines.length > keepLines) {
        const truncatedContent = lines.slice(-keepLines).join('\n');
        const originalSize = file.size;
        
        // Add truncation notice at the beginning
        const notice = `// LOG TRUNCATED on ${new Date().toISOString()} - keeping last ${keepLines} lines\n`;
        fs.writeFileSync(file.path, notice + truncatedContent);
        
        const newSize = fs.statSync(file.path).size;
        const savedSize = originalSize - newSize;
        
        console.log(`${colors.green}Truncated: ${file.name}${colors.reset} (saved ${formatFileSize(savedSize)})`);
        processedCount++;
      }
    } catch (error) {
      console.log(`${colors.red}Error truncating ${file.name}: ${error.message}${colors.reset}`);
    }
  });

  console.log(`\n${colors.bright}${colors.green}Truncation completed:${colors.reset}`);
  console.log(`Files processed: ${processedCount}`);
}

// Function to show log statistics
function showStats() {
  if (!fs.existsSync(logsDir)) {
    console.log(`${colors.red}Logs directory not found: ${logsDir}${colors.reset}`);
    return;
  }

  const files = fs.readdirSync(logsDir)
    .filter(file => file.endsWith('.log'))
    .map(file => {
      const filePath = path.join(logsDir, file);
      const stat = fs.statSync(filePath);
      const age = getFileAgeDays(filePath);
      return {
        name: file,
        size: stat.size,
        age: age,
        modified: stat.mtime
      };
    });

  if (files.length === 0) {
    console.log(`${colors.yellow}No log files found.${colors.reset}`);
    return;
  }

  const totalSize = files.reduce((sum, file) => sum + file.size, 0);
  const avgAge = Math.round(files.reduce((sum, file) => sum + file.age, 0) / files.length);
  const oldFiles = files.filter(file => file.age > DEFAULT_RETENTION_DAYS);
  const largeFiles = files.filter(file => file.size > DEFAULT_MAX_SIZE_MB * 1024 * 1024);

  console.log(`${colors.bright}${colors.blue}Log Directory Statistics:${colors.reset}\n`);
  console.log(`Directory: ${logsDir}`);
  console.log(`Total files: ${files.length}`);
  console.log(`Total size: ${formatFileSize(totalSize)}`);
  console.log(`Average age: ${avgAge} days`);
  console.log(`Files older than ${DEFAULT_RETENTION_DAYS} days: ${oldFiles.length}`);
  console.log(`Files larger than ${DEFAULT_MAX_SIZE_MB}MB: ${largeFiles.length}`);

  console.log(`\n${colors.bright}${colors.blue}Recent files (last 10):${colors.reset}`);
  files
    .sort((a, b) => b.modified - a.modified)
    .slice(0, 10)
    .forEach(file => {
      const sizeStr = formatFileSize(file.size);
      const ageStr = file.age === 0 ? 'today' : `${file.age} days ago`;
      console.log(`${colors.green}${file.name}${colors.reset} (${sizeStr}, ${ageStr})`);
    });
}

// Main function
function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  
  switch (command) {
    case 'clean':
    case 'old':
      const retentionDays = parseInt(args[1]) || DEFAULT_RETENTION_DAYS;
      const dryRun = args.includes('--dry-run') || args.includes('-n');
      cleanOldLogs(retentionDays, dryRun);
      break;

    case 'truncate':
    case 'large':
      const maxSizeMB = parseInt(args[1]) || DEFAULT_MAX_SIZE_MB;
      const dryRunTruncate = args.includes('--dry-run') || args.includes('-n');
      cleanLargeFiles(maxSizeMB, dryRunTruncate);
      break;

    case 'stats':
    case 'status':
      showStats();
      break;

    case 'full':
      console.log(`${colors.bright}${colors.blue}Full cleanup starting...${colors.reset}\n`);
      const fullDryRun = args.includes('--dry-run') || args.includes('-n');
      cleanOldLogs(DEFAULT_RETENTION_DAYS, fullDryRun);
      console.log('');
      cleanLargeFiles(DEFAULT_MAX_SIZE_MB, fullDryRun);
      break;

    default:
      console.log(`${colors.bright}${colors.blue}Cyber Range Log Cleanup Tool${colors.reset}\n`);
      console.log('Usage:');
      console.log(`  ${colors.green}node log-cleanup.js clean [days] [--dry-run]${colors.reset}     - Remove logs older than N days (default: ${DEFAULT_RETENTION_DAYS})`);
      console.log(`  ${colors.green}node log-cleanup.js truncate [sizeMB] [--dry-run]${colors.reset} - Truncate logs larger than N MB (default: ${DEFAULT_MAX_SIZE_MB})`);
      console.log(`  ${colors.green}node log-cleanup.js stats${colors.reset}                       - Show log directory statistics`);
      console.log(`  ${colors.green}node log-cleanup.js full [--dry-run]${colors.reset}            - Run full cleanup (old + large files)`);
      console.log('\nExamples:');
      console.log(`  ${colors.dim}node log-cleanup.js clean 7 --dry-run${colors.reset}    - Show what would be deleted (7+ days old)`);
      console.log(`  ${colors.dim}node log-cleanup.js truncate 50${colors.reset}          - Truncate files larger than 50MB`);
      console.log(`  ${colors.dim}node log-cleanup.js stats${colors.reset}                - Show current log statistics`);
      console.log(`  ${colors.dim}node log-cleanup.js full${colors.reset}                 - Clean old files and truncate large ones`);
      console.log('\nOptions:');
      console.log(`  ${colors.yellow}--dry-run, -n${colors.reset}   - Show what would be done without making changes`);
      break;
  }
}

// Run the main function
main();
