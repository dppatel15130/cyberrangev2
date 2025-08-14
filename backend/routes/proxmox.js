const express = require('express');
const { auth: authenticateToken, admin: requireAdmin } = require('../middleware/auth');
const proxmoxService = require('../services/proxmoxService');
const router = express.Router();

// Get Proxmox system status and VM inventory
router.get('/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const status = await proxmoxService.getSystemStatus();
    res.json(status);
  } catch (error) {
    console.error('Error getting Proxmox status:', error);
    res.status(500).json({ error: 'Failed to get Proxmox status' });
  }
});

// Get all VMs from Proxmox
router.get('/vms', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const vmList = await proxmoxService.getVMList();
    res.json({
      vms: vmList,
      total: vmList.length,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('Error getting VM list:', error);
    res.status(500).json({ error: 'Failed to get VM list' });
  }
});

// Get specific VM status
router.get('/vms/:vmId/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const vmId = parseInt(req.params.vmId);
    const vmStatus = await proxmoxService.getVMStatus(vmId);
    
    if (!vmStatus) {
      return res.status(404).json({ error: 'VM not found' });
    }
    
    res.json(vmStatus);
  } catch (error) {
    console.error('Error getting VM status:', error);
    res.status(500).json({ error: 'Failed to get VM status' });
  }
});

// Start VM
router.post('/vms/:vmId/start', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const vmId = parseInt(req.params.vmId);
    const result = await proxmoxService.startVM(vmId);
    
    if (result) {
      res.json({ 
        success: true, 
        message: `VM ${vmId} start command sent`,
        vmId 
      });
    } else {
      res.status(500).json({ error: 'Failed to start VM' });
    }
  } catch (error) {
    console.error('Error starting VM:', error);
    res.status(500).json({ error: 'Failed to start VM' });
  }
});

// Stop VM
router.post('/vms/:vmId/stop', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const vmId = parseInt(req.params.vmId);
    const result = await proxmoxService.stopVM(vmId);
    
    if (result) {
      res.json({ 
        success: true, 
        message: `VM ${vmId} stop command sent`,
        vmId 
      });
    } else {
      res.status(500).json({ error: 'Failed to stop VM' });
    }
  } catch (error) {
    console.error('Error stopping VM:', error);
    res.status(500).json({ error: 'Failed to stop VM' });
  }
});

// Shutdown VM gracefully
router.post('/vms/:vmId/shutdown', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const vmId = parseInt(req.params.vmId);
    const result = await proxmoxService.shutdownVM(vmId);
    
    if (result) {
      res.json({ 
        success: true, 
        message: `VM ${vmId} shutdown command sent`,
        vmId 
      });
    } else {
      res.status(500).json({ error: 'Failed to shutdown VM' });
    }
  } catch (error) {
    console.error('Error shutting down VM:', error);
    res.status(500).json({ error: 'Failed to shutdown VM' });
  }
});

// Get available VMs for assignment
router.get('/vms/available', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { type, role } = req.query;
    const filters = {};
    
    if (type) filters.type = type;
    if (role) filters.role = role;
    
    const availableVMs = proxmoxService.getAvailableVMs(filters);
    
    res.json({
      available: availableVMs,
      total: availableVMs.length,
      filters: filters
    });
  } catch (error) {
    console.error('Error getting available VMs:', error);
    res.status(500).json({ error: 'Failed to get available VMs' });
  }
});

// Get VM assignments for a match
router.get('/matches/:matchId/assignments', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const matchId = parseInt(req.params.matchId);
    const assignments = proxmoxService.getMatchAssignments(matchId);
    
    res.json({
      matchId,
      assignments,
      totalTeams: Object.keys(assignments).length,
      totalVMs: Object.values(assignments).reduce((sum, teamVMs) => sum + teamVMs.length, 0)
    });
  } catch (error) {
    console.error('Error getting match assignments:', error);
    res.status(500).json({ error: 'Failed to get match assignments' });
  }
});

// Assign VMs to a team for a match
router.post('/matches/:matchId/teams/:teamId/assign', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const matchId = parseInt(req.params.matchId);
    const teamId = parseInt(req.params.teamId);
    const { vmRequirements } = req.body;
    
    if (!vmRequirements || !Array.isArray(vmRequirements)) {
      return res.status(400).json({ error: 'VM requirements array is required' });
    }
    
    const result = await proxmoxService.assignVMsToTeam(matchId, teamId, vmRequirements);
    
    if (result.success) {
      res.json({
        success: true,
        matchId,
        teamId,
        assignedVMs: result.assignedVMs,
        message: result.message
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.error
      });
    }
  } catch (error) {
    console.error('Error assigning VMs:', error);
    res.status(500).json({ error: 'Failed to assign VMs' });
  }
});

// Release VMs for a team
router.post('/matches/:matchId/teams/:teamId/release', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const matchId = parseInt(req.params.matchId);
    const teamId = parseInt(req.params.teamId);
    
    const result = await proxmoxService.releaseTeamVMs(matchId, teamId);
    
    if (result.success) {
      res.json({
        success: true,
        matchId,
        teamId,
        releasedCount: result.releasedCount,
        message: result.message
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.error
      });
    }
  } catch (error) {
    console.error('Error releasing team VMs:', error);
    res.status(500).json({ error: 'Failed to release team VMs' });
  }
});

// Start all VMs for a match
router.post('/matches/:matchId/vms/start', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const matchId = parseInt(req.params.matchId);
    
    const result = await proxmoxService.startMatchVMs(matchId);
    
    if (result.success) {
      res.json({
        success: true,
        matchId,
        results: result.results,
        message: result.message
      });
    } else {
      res.status(500).json({
        success: false,
        error: result.error
      });
    }
  } catch (error) {
    console.error('Error starting match VMs:', error);
    res.status(500).json({ error: 'Failed to start match VMs' });
  }
});

// Stop all VMs for a match
router.post('/matches/:matchId/vms/stop', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const matchId = parseInt(req.params.matchId);
    
    const result = await proxmoxService.stopMatchVMs(matchId);
    
    if (result.success) {
      res.json({
        success: true,
        matchId,
        results: result.results,
        message: result.message
      });
    } else {
      res.status(500).json({
        success: false,
        error: result.error
      });
    }
  } catch (error) {
    console.error('Error stopping match VMs:', error);
    res.status(500).json({ error: 'Failed to stop match VMs' });
  }
});

// Release all VMs for a match
router.post('/matches/:matchId/vms/release', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const matchId = parseInt(req.params.matchId);
    
    const result = await proxmoxService.releaseMatchVMs(matchId);
    
    if (result.success) {
      res.json({
        success: true,
        matchId,
        releasedCount: result.releasedCount,
        message: result.message
      });
    } else {
      res.status(500).json({
        success: false,
        error: result.error
      });
    }
  } catch (error) {
    console.error('Error releasing match VMs:', error);
    res.status(500).json({ error: 'Failed to release match VMs' });
  }
});

// Proxmox API health check
router.get('/health', authenticateToken, async (req, res) => {
  try {
    const healthCheck = await proxmoxService.healthCheck();
    res.json(healthCheck);
  } catch (error) {
    console.error('Error checking Proxmox health:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Health check failed' 
    });
  }
});

// Get VM inventory summary
router.get('/inventory', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const availableVMs = proxmoxService.getAvailableVMs();
    
    // Group by type and role
    const inventory = {
      summary: {
        total: availableVMs.length,
        available: availableVMs.filter(vm => vm.status === 'available').length,
        assigned: availableVMs.filter(vm => vm.status === 'assigned').length
      },
      byType: {
        kali: availableVMs.filter(vm => vm.type === 'kali').length,
        windows: availableVMs.filter(vm => vm.type === 'windows').length
      },
      byRole: {
        attacker: availableVMs.filter(vm => vm.role === 'attacker').length,
        target: availableVMs.filter(vm => vm.role === 'target').length
      },
      vms: availableVMs
    };

    res.json(inventory);
  } catch (error) {
    console.error('Error getting VM inventory:', error);
    res.status(500).json({ error: 'Failed to get VM inventory' });
  }
});

// Get VM templates/configurations
router.get('/templates', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const templates = {
      attackDefense: [
        { type: 'windows', role: 'target', name: 'Windows Target', description: 'Windows machine for exploitation' },
        { type: 'kali', role: 'attacker', name: 'Kali Attacker', description: 'Kali Linux for penetration testing' }
      ],
      kingOfHill: [
        { type: 'kali', role: 'attacker', name: 'Kali Attacker', description: 'Kali Linux for attacks' },
        { type: 'kali', role: 'attacker', name: 'Kali Attacker 2', description: 'Second Kali for team' }
      ],
      ctf: [
        { type: 'windows', role: 'target', name: 'Windows Challenge', description: 'Windows with challenges' },
        { type: 'kali', role: 'attacker', name: 'Kali Solver', description: 'Kali for solving challenges' }
      ]
    };

    res.json({
      templates,
      available: proxmoxService.getAvailableVMs(),
      timestamp: new Date()
    });
  } catch (error) {
    console.error('Error getting VM templates:', error);
    res.status(500).json({ error: 'Failed to get VM templates' });
  }
});

module.exports = router;
