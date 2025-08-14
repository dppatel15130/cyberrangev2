const { sequelize } = require('../config/db');
const axios = require('axios');
const util = require('util');
const exec = util.promisify(require('child_process').exec);
const https = require('https');
require('dotenv').config();

// Helper function to check if a service is reachable
async function checkService(service) {
  try {
    switch(service.type) {
      case 'http':
        const response = await axios({
          method: service.method || 'GET',
          url: service.url,
          headers: service.headers,
          data: service.data,
          timeout: service.timeout || 5000,
          validateStatus: () => true
        });
        return {
          status: service.successStatus ? response.status === service.successStatus : response.status < 400,
          data: response.data,
          statusCode: response.status
        };

      case 'ping':
        const { stdout, stderr } = await exec(`ping -c 1 -W 2 ${service.host}`);
        return { status: !stderr && stdout.includes('1 received') };

      case 'tcp':
        const net = require('net');
        return new Promise((resolve) => {
          const client = new net.Socket();
          let connected = false;

          client.setTimeout(2000);

          client.on('connect', () => {
            connected = true;
            client.destroy();
            resolve({ status: true });
          });

          client.on('timeout', () => {
            client.destroy();
            resolve({ status: false, error: 'Connection timeout' });
          });

          client.on('error', () => {
            client.destroy();
            resolve({ status: false, error: 'Connection error' });
          });

          client.connect(service.port, service.host);
        });

      case 'mysql':
        try {
          const mysql = require('mysql2/promise');
          const connection = await mysql.createConnection({
            host: service.host,
            port: service.port,
            user: service.user,
            password: service.password,
            database: service.database,
            connectTimeout: service.timeout || 2000
          });
          await connection.ping();
          await connection.end();
          return { status: true };
        } catch (error) {
          console.error('Database connection error:', error);
          return { status: false, error: error.message };
        }

      case 'proxmox':
        try {
          const response = await axios.get(`${service.host}/api2/json/version`, {
            headers: {
              'Authorization': `PVEAPIToken=${service.tokenID}=${service.tokenValue}`,
            },
            httpsAgent: new https.Agent({ rejectUnauthorized: false }),
            timeout: 5000
          });
          return {
            status: response.status === 200,
            statusCode: response.status,
            data: response.data
          };
        } catch (error) {
          console.error('Proxmox connection error:', error.message);
          return {
            status: false,
            error: error.message,
            statusCode: error.response?.status
          };
        }

      default:
        return { status: false, error: 'Unknown service type' };
    }
  } catch (error) {
    return { status: false, error: error.message };
  }
}

exports.getStatus = async (req, res) => {
  const startTime = Date.now();

  const services = {
    database: {
      type: 'mysql',
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      timeout: 2000
    },
    proxmox: {
      type: 'proxmox',
      host: process.env.PROXMOX_API_URL,            // Example: https://172.16.200.129:8006
      tokenID: process.env.PROXMOX_API_TOKEN_NAME,   // Format: user@realm!tokenname
      tokenValue: process.env.PROXMOX_API_TOKEN_VALUE
    },
    guacamole: {
      type: 'http',
      method: 'POST',
      url: `${process.env.GUACAMOLE_API_URL}/tokens`,
      data: `username=${process.env.GUACAMOLE_USERNAME}&password=${process.env.GUACAMOLE_PASSWORD}`,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      successStatus: 200
    }
  };

  const [dbCheck, proxmoxCheck, guacCheck] = await Promise.all([
    checkService(services.database).catch(e => ({ status: false, error: e.message })),
    checkService(services.proxmox).catch(e => ({ status: false, error: e.message })),
    checkService(services.guacamole).catch(e => ({ status: false, error: e.message }))
  ]);

  const response = {
    server: 'Online',
    database: dbCheck.status ? 'Connected' : 'Disconnected',
    proxmox: proxmoxCheck.status ? 'Connected' : 'Disconnected',
    guacamole: guacCheck.status ? 'Connected' : 'Disconnected',
    timestamp: new Date().toISOString(),
    responseTime: Date.now() - startTime + 'ms',
    details: {
      database: dbCheck,
      proxmox: proxmoxCheck,
      guacamole: guacCheck
    }
  };

  console.log('[STATUS]', JSON.stringify({
    timestamp: response.timestamp,
    status: {
      database: response.database,
      proxmox: response.proxmox,
      guacamole: response.guacamole
    },
    responseTime: response.responseTime
  }, null, 2));

  res.json(response);
};
