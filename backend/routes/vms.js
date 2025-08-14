const express = require('express');
const router = express.Router();
const vmController = require('../controllers/vmController');
const { auth, admin } = require('../middleware/auth');

// VM listing routes - put specific routes before generic /:vmId route
router.get('/', auth, admin, vmController.getAllActiveVMs);      // List only active VMs from database
router.get('/all', auth, admin, vmController.listAllVMs);        // List all VMs with details
router.get('/lab/:labId', auth, vmController.getVMByLabId);
router.get('/status/proxmox/:proxmoxVmId', auth, vmController.getProxmoxVMStatus);

// VM management routes
router.post('/start', auth, vmController.startLabVM);
router.post('/:vmId/stop', auth, vmController.stopLabVM);

// Generic /:vmId route - must be LAST to avoid conflicts
router.get('/:vmId', auth, vmController.getVMStatus);

module.exports = router;