#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const logsDir = path.join(__dirname, '../logs');

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bright: '\x1b[1m',
  dim: '\x1b[2m'
};

// Function to colorize log levels
function colorizeLevel(level) {
  switch (level.toLowerCase()) {
    case 'error':
      return `${colors.red}${colors.bright}${level}${colors.reset}`;
    case 'warn':
    case 'warning':
      return `${colors.yellow}${colors.bright}${level}${colors.reset}`;
    case 'info':
      return `${colors.blue}${level}${colors.reset}`;
    case 'debug':
      return `${colors.dim}${level}${colors.reset}`;
    default:
      return level;
  }
}

// Function to colorize categories
function colorizeCategory(category) {
  switch (category) {
    case 'ACCESS':
      return `${colors.cyan}${category}${colors.reset}`;
    case 'AUTH':
      return `${colors.green}${category}${colors.reset}`;
    case 'SECURITY':
      return `${colors.red}${colors.bright}${category}${colors.reset}`;
    case 'VM_OPERATIONS':
      return `${colors.magenta}${category}${colors.reset}`;
    case 'LAB_OPERATIONS':
      return `${colors.blue}${category}${colors.reset}`;
    case 'DATABASE':
      return `${colors.yellow}${category}${colors.reset}`;
    case 'ERROR':
      return `${colors.red}${category}${colors.reset}`;
    default:
      return category;
  }
}

// Function to get available log files
function getLogFiles() {
  if (!fs.existsSync(logsDir)) {
    console.log(`${colors.red}Logs directory not found: ${logsDir}${colors.reset}`);
    return [];
  }

  const files = fs.readdirSync(logsDir)
    .filter(file => file.endsWith('.log'))
    .map(file => {
      const stat = fs.statSync(path.join(logsDir, file));
      return {
        name: file,
        size: stat.size,
        modified: stat.mtime
      };
    })
    .sort((a, b) => b.modified - a.modified);

  return files;
}

// Function to format file size
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Function to tail a log file
function tailLogFile(filename, lines = 50) {
  const filePath = path.join(logsDir, filename);
  
  if (!fs.existsSync(filePath)) {
    console.log(`${colors.red}Log file not found: ${filename}${colors.reset}`);
    return;
  }

  const fileContent = fs.readFileSync(filePath, 'utf8');
  const logLines = fileContent.split('\n').filter(line => line.trim() !== '');
  const recentLines = logLines.slice(-lines);

  console.log(`${colors.bright}${colors.blue}=== Last ${lines} lines from ${filename} ===${colors.reset}\n`);

  recentLines.forEach(line => {
    // Try to parse and colorize the line
    const timestampMatch = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
    const levelMatch = line.match(/\[(\w+)\]/);
    const categoryMatch = line.match(/"category":"(\w+)"/);

    if (timestampMatch && levelMatch) {
      const timestamp = `${colors.dim}${timestampMatch[1]}${colors.reset}`;
      const level = colorizeLevel(levelMatch[1]);
      let processedLine = line.replace(timestampMatch[1], timestamp);
      processedLine = processedLine.replace(`[${levelMatch[1]}]`, `[${level}]`);
      
      if (categoryMatch) {
        const category = colorizeCategory(categoryMatch[1]);
        processedLine = processedLine.replace(`"category":"${categoryMatch[1]}"`, `"category":"${category}"`);
      }
      
      console.log(processedLine);
    } else {
      console.log(line);
    }
  });
}

// Function to follow a log file (like tail -f)
function followLogFile(filename) {
  const filePath = path.join(logsDir, filename);
  
  if (!fs.existsSync(filePath)) {
    console.log(`${colors.red}Log file not found: ${filename}${colors.reset}`);
    return;
  }

  console.log(`${colors.bright}${colors.green}Following ${filename} (Press Ctrl+C to stop)${colors.reset}\n`);

  let lastSize = fs.statSync(filePath).size;

  // Read existing content first
  tailLogFile(filename, 20);
  console.log(`${colors.dim}--- Following new entries ---${colors.reset}\n`);

  const interval = setInterval(() => {
    const currentSize = fs.statSync(filePath).size;
    
    if (currentSize > lastSize) {
      const stream = fs.createReadStream(filePath, {
        start: lastSize,
        end: currentSize
      });
      
      let buffer = '';
      stream.on('data', chunk => {
        buffer += chunk;
      });
      
      stream.on('end', () => {
        const newLines = buffer.split('\n').filter(line => line.trim() !== '');
        newLines.forEach(line => {
          const timestampMatch = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
          const levelMatch = line.match(/\[(\w+)\]/);
          const categoryMatch = line.match(/"category":"(\w+)"/);

          if (timestampMatch && levelMatch) {
            const timestamp = `${colors.dim}${timestampMatch[1]}${colors.reset}`;
            const level = colorizeLevel(levelMatch[1]);
            let processedLine = line.replace(timestampMatch[1], timestamp);
            processedLine = processedLine.replace(`[${levelMatch[1]}]`, `[${level}]`);
            
            if (categoryMatch) {
              const category = colorizeCategory(categoryMatch[1]);
              processedLine = processedLine.replace(`"category":"${categoryMatch[1]}"`, `"category":"${category}"`);
            }
            
            console.log(processedLine);
          } else {
            console.log(line);
          }
        });
      });
      
      lastSize = currentSize;
    }
  }, 1000);

  // Handle Ctrl+C
  process.on('SIGINT', () => {
    clearInterval(interval);
    console.log(`\n${colors.yellow}Stopped following ${filename}${colors.reset}`);
    process.exit(0);
  });
}

// Main function
function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const filename = args[1];

  switch (command) {
    case 'list':
    case 'ls':
      const files = getLogFiles();
      if (files.length === 0) {
        console.log(`${colors.yellow}No log files found in ${logsDir}${colors.reset}`);
        return;
      }
      
      console.log(`${colors.bright}${colors.blue}Available log files:${colors.reset}\n`);
      files.forEach(file => {
        const sizeStr = formatFileSize(file.size);
        const modifiedStr = file.modified.toLocaleString();
        console.log(`${colors.green}${file.name}${colors.reset} (${sizeStr}, modified: ${modifiedStr})`);
      });
      break;

    case 'tail':
      if (!filename) {
        console.log(`${colors.red}Usage: node log-viewer.js tail <filename> [lines]${colors.reset}`);
        return;
      }
      const lines = parseInt(args[2]) || 50;
      tailLogFile(filename, lines);
      break;

    case 'follow':
    case 'f':
      if (!filename) {
        console.log(`${colors.red}Usage: node log-viewer.js follow <filename>${colors.reset}`);
        return;
      }
      followLogFile(filename);
      break;

    case 'errors':
      console.log(`${colors.bright}${colors.red}Recent errors:${colors.reset}\n`);
      tailLogFile('error-' + new Date().toISOString().split('T')[0] + '.log', 30);
      break;

    case 'security':
      console.log(`${colors.bright}${colors.red}Recent security events:${colors.reset}\n`);
      tailLogFile('security-' + new Date().toISOString().split('T')[0] + '.log', 30);
      break;

    case 'auth':
      console.log(`${colors.bright}${colors.green}Recent authentication events:${colors.reset}\n`);
      tailLogFile('auth-' + new Date().toISOString().split('T')[0] + '.log', 30);
      break;

    case 'access':
      console.log(`${colors.bright}${colors.cyan}Recent access logs:${colors.reset}\n`);
      tailLogFile('access-' + new Date().toISOString().split('T')[0] + '.log', 30);
      break;

    default:
      console.log(`${colors.bright}${colors.blue}Cyber Range Log Viewer${colors.reset}\n`);
      console.log('Usage:');
      console.log(`  ${colors.green}node log-viewer.js list${colors.reset}                    - List all available log files`);
      console.log(`  ${colors.green}node log-viewer.js tail <filename> [lines]${colors.reset} - Show last N lines of a log file`);
      console.log(`  ${colors.green}node log-viewer.js follow <filename>${colors.reset}       - Follow a log file in real-time`);
      console.log(`  ${colors.green}node log-viewer.js errors${colors.reset}                 - Show recent errors`);
      console.log(`  ${colors.green}node log-viewer.js security${colors.reset}               - Show recent security events`);
      console.log(`  ${colors.green}node log-viewer.js auth${colors.reset}                   - Show recent authentication events`);
      console.log(`  ${colors.green}node log-viewer.js access${colors.reset}                 - Show recent access logs`);
      console.log('\nExamples:');
      console.log(`  ${colors.dim}node log-viewer.js list${colors.reset}`);
      console.log(`  ${colors.dim}node log-viewer.js tail application-2024-01-15.log 100${colors.reset}`);
      console.log(`  ${colors.dim}node log-viewer.js follow error-2024-01-15.log${colors.reset}`);
      break;
  }
}

// Run the main function
main();
