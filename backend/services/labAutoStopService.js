/**
 * Lab Auto-Stop Service for Cyber Range Training Platform
 * 
 * This service provides automated stopping of lab VMs after a predefined duration.
 * Features:
 * - Timer-based auto-stop using setTimeout
 * - Persistence across server restarts
 * - Conflict prevention with manual stop operations
 * - Comprehensive logging and error handling
 * - Memory-efficient timeout management
 */

const { VM, Lab, User } = require('../models');
const { Op } = require('sequelize');
const vmController = require('../controllers/vmController');

/**
 * In-memory store for active auto-stop timers
 * Structure: { vmId: { timeoutId, scheduledAt, stopTime, labDuration } }
 */
const activeTimers = new Map();

/**
 * Logs auto-stop related events with structured format
 * @param {string} level - Log level (INFO, WARN, ERROR)
 * @param {string} message - Log message
 * @param {object} metadata - Additional context data
 */
function logAutoStop(level, message, metadata = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level,
    service: 'LabAutoStop',
    message,
    ...metadata
  };
  
  console.log(`[${level}] [LabAutoStop] ${message}`, 
    Object.keys(metadata).length > 0 ? JSON.stringify(metadata, null, 2) : '');
}

/**
 * Safely calls the existing stopLabVM function to avoid code duplication
 * @param {number} vmDatabaseId - Database ID of the VM record
 * @param {object} userContext - User context for the stop operation
 * @returns {Promise<boolean>} - Success status
 */
async function stopVMSafely(vmDatabaseId, userContext) {
  try {
    // Create a mock request object similar to Express request
    const mockReq = {
      params: { vmId: vmDatabaseId },
      user: userContext
    };

    // Create a mock response object to capture the result
    let responseData = null;
    let statusCode = 200;
    const mockRes = {
      status: (code) => {
        statusCode = code;
        return mockRes;
      },
      json: (data) => {
        responseData = data;
        return mockRes;
      }
    };

    // Call the existing stopLabVM controller function
    await vmController.stopLabVM(mockReq, mockRes);
    
    if (statusCode >= 200 && statusCode < 300) {
      logAutoStop('INFO', 'VM stopped successfully via auto-stop', {
        vmDatabaseId,
        statusCode,
        response: responseData
      });
      return true;
    } else {
      logAutoStop('WARN', 'VM stop returned non-success status', {
        vmDatabaseId,
        statusCode,
        response: responseData
      });
      return false;
    }
  } catch (error) {
    logAutoStop('ERROR', 'Failed to stop VM via auto-stop', {
      vmDatabaseId,
      error: error.message,
      stack: error.stack
    });
    return false;
  }
}

/**
 * Executes the auto-stop for a specific VM
 * @param {number} vmDatabaseId - Database ID of the VM record
 * @param {object} labInfo - Lab information
 * @param {object} userInfo - User information
 */
async function executeAutoStop(vmDatabaseId, labInfo, userInfo) {
  logAutoStop('INFO', 'Executing auto-stop for VM', {
    vmDatabaseId,
    labId: labInfo.id,
    labName: labInfo.name,
    userId: userInfo.id,
    username: userInfo.username
  });

  try {
    // First, check if the VM still exists and is running
    const currentVM = await VM.findByPk(vmDatabaseId, {
      include: [
        {
          model: User,
          as: 'user',
          attributes: ['id', 'username', 'email', 'role']
        },
        {
          model: Lab,
          as: 'lab', // Make sure this association exists in your models
          attributes: ['id', 'name', 'duration']
        }
      ]
    });

    if (!currentVM) {
      logAutoStop('WARN', 'VM not found during auto-stop execution', {
        vmDatabaseId
      });
      return;
    }

    if (currentVM.status !== 'running') {
      logAutoStop('INFO', 'VM is not running, skipping auto-stop', {
        vmDatabaseId,
        currentStatus: currentVM.status
      });
      return;
    }

    // Check if VM has been manually stopped recently
    if (currentVM.endTime && 
        new Date(currentVM.endTime) > new Date(Date.now() - 5 * 60 * 1000)) {
      logAutoStop('INFO', 'VM was manually stopped recently, skipping auto-stop', {
        vmDatabaseId,
        endTime: currentVM.endTime
      });
      return;
    }

    // Create user context for the stop operation (prefer VM owner over original user)
    const stopUserContext = {
      id: currentVM.user.id,
      username: currentVM.user.username,
      email: currentVM.user.email,
      role: currentVM.user.role || 'user'
    };

    // Attempt to stop the VM
    const stopSuccess = await stopVMSafely(vmDatabaseId, stopUserContext);
    
    if (stopSuccess) {
      logAutoStop('INFO', 'Auto-stop completed successfully', {
        vmDatabaseId,
        labId: labInfo.id,
        labName: labInfo.name,
        userId: userInfo.id,
        duration: labInfo.duration
      });
    } else {
      logAutoStop('ERROR', 'Auto-stop failed to stop VM', {
        vmDatabaseId,
        labId: labInfo.id
      });
    }

  } catch (error) {
    logAutoStop('ERROR', 'Error during auto-stop execution', {
      vmDatabaseId,
      error: error.message,
      stack: error.stack
    });
  } finally {
    // Always clean up the timer from memory
    activeTimers.delete(vmDatabaseId);
    logAutoStop('INFO', 'Auto-stop timer cleaned up', {
      vmDatabaseId,
      activeTimersCount: activeTimers.size
    });
  }
}

/**
 * Schedules an auto-stop for a lab VM
 * @param {number} vmDatabaseId - Database ID of the VM record
 * @param {number} labId - Lab ID
 * @param {number} durationInMinutes - Duration before auto-stop
 * @param {object} userContext - User context information
 * @returns {Promise<boolean>} - Success status
 */
async function scheduleLabAutoStop(vmDatabaseId, labId, durationInMinutes, userContext = null) {
  try {
    // Validate input parameters
    if (!vmDatabaseId || !labId || !durationInMinutes) {
      logAutoStop('ERROR', 'Invalid parameters for scheduling auto-stop', {
        vmDatabaseId,
        labId,
        durationInMinutes
      });
      return false;
    }

    if (durationInMinutes <= 0 || durationInMinutes > 1440) { // Max 24 hours
      logAutoStop('WARN', 'Duration out of acceptable range', {
        vmDatabaseId,
        durationInMinutes,
        message: 'Duration must be between 1 and 1440 minutes'
      });
      return false;
    }

    // Check if there's already a timer for this VM
    if (activeTimers.has(vmDatabaseId)) {
      logAutoStop('WARN', 'Timer already exists for VM, clearing old timer', {
        vmDatabaseId
      });
      const existingTimer = activeTimers.get(vmDatabaseId);
      clearTimeout(existingTimer.timeoutId);
      activeTimers.delete(vmDatabaseId);
    }

    // Get lab and user information for context
    const labInfo = await Lab.findByPk(labId, {
      attributes: ['id', 'name', 'duration', 'labType']
    });

    if (!labInfo) {
      logAutoStop('ERROR', 'Lab not found for auto-stop scheduling', {
        vmDatabaseId,
        labId
      });
      return false;
    }

    // Get VM information to verify it exists and get user context
    const vmInfo = await VM.findByPk(vmDatabaseId, {
      include: [
        {
          model: User,
          as: 'user',
          attributes: ['id', 'username', 'email']
        }
      ]
    });

    if (!vmInfo) {
      logAutoStop('ERROR', 'VM not found for auto-stop scheduling', {
        vmDatabaseId
      });
      return false;
    }

    // Use provided user context or fall back to VM owner
    const effectiveUserContext = userContext || {
      id: vmInfo.user.id,
      username: vmInfo.user.username,
      email: vmInfo.user.email
    };

    // Calculate timeout duration in milliseconds
    const timeoutMs = durationInMinutes * 60 * 1000;
    const scheduledAt = new Date();
    const stopTime = new Date(Date.now() + timeoutMs);

    logAutoStop('INFO', 'Scheduling auto-stop for VM', {
      vmDatabaseId,
      labId,
      labName: labInfo.name,
      userId: effectiveUserContext.id,
      username: effectiveUserContext.username,
      durationMinutes: durationInMinutes,
      scheduledAt: scheduledAt.toISOString(),
      stopTime: stopTime.toISOString()
    });

    // Schedule the auto-stop
    const timeoutId = setTimeout(() => {
      executeAutoStop(vmDatabaseId, labInfo, effectiveUserContext);
    }, timeoutMs);

    // Store timer information
    activeTimers.set(vmDatabaseId, {
      timeoutId,
      scheduledAt,
      stopTime,
      labDuration: durationInMinutes,
      labId,
      labName: labInfo.name,
      userId: effectiveUserContext.id,
      username: effectiveUserContext.username
    });

    logAutoStop('INFO', 'Auto-stop scheduled successfully', {
      vmDatabaseId,
      labId,
      timeoutMs,
      activeTimersCount: activeTimers.size
    });

    return true;

  } catch (error) {
    logAutoStop('ERROR', 'Failed to schedule auto-stop', {
      vmDatabaseId,
      labId,
      error: error.message,
      stack: error.stack
    });
    return false;
  }
}

/**
 * Cancels an auto-stop timer for a specific VM
 * @param {number} vmDatabaseId - Database ID of the VM record
 * @returns {boolean} - Success status
 */
function cancelLabAutoStop(vmDatabaseId) {
  if (activeTimers.has(vmDatabaseId)) {
    const timer = activeTimers.get(vmDatabaseId);
    clearTimeout(timer.timeoutId);
    activeTimers.delete(vmDatabaseId);
    
    logAutoStop('INFO', 'Auto-stop timer cancelled', {
      vmDatabaseId,
      scheduledStopTime: timer.stopTime?.toISOString(),
      activeTimersCount: activeTimers.size
    });
    
    return true;
  } else {
    logAutoStop('WARN', 'No active timer found to cancel', {
      vmDatabaseId
    });
    return false;
  }
}

/**
 * Gets information about active auto-stop timers
 * @param {number} vmDatabaseId - Optional specific VM ID to check
 * @returns {object|array} - Timer information
 */
function getActiveTimers(vmDatabaseId = null) {
  if (vmDatabaseId !== null) {
    const timer = activeTimers.get(vmDatabaseId);
    if (timer) {
      return {
        vmDatabaseId,
        ...timer,
        timeRemainingMs: timer.stopTime.getTime() - Date.now(),
        isActive: true
      };
    }
    return null;
  }

  // Return all active timers
  const timersArray = [];
  for (const [vmId, timer] of activeTimers.entries()) {
    timersArray.push({
      vmDatabaseId: vmId,
      ...timer,
      timeRemainingMs: timer.stopTime.getTime() - Date.now(),
      isActive: true
    });
  }

  return timersArray;
}

/**
 * Recovers auto-stop timers after server restart
 * This function should be called on application startup
 */
async function recoverAutoStopTimers() {
  try {
    logAutoStop('INFO', 'Starting auto-stop timer recovery after server restart');

    // Find all running VMs
    const runningVMs = await VM.findAll({
      where: {
        status: 'running'
      },
      include: [
        {
          model: User,
          as: 'user',
          attributes: ['id', 'username', 'email']
        },
        {
          model: Lab,
          as: 'lab', // Make sure this association exists
          attributes: ['id', 'name', 'duration']
        }
      ]
    });

    logAutoStop('INFO', 'Found running VMs for timer recovery', {
      count: runningVMs.length
    });

    let recoveredCount = 0;
    let skippedCount = 0;

    for (const vm of runningVMs) {
      if (!vm.lab) {
        logAutoStop('WARN', 'VM has no associated lab, skipping recovery', {
          vmDatabaseId: vm.id
        });
        skippedCount++;
        continue;
      }

      // Calculate how much time has elapsed since VM start
      const startTime = new Date(vm.startTime);
      const now = new Date();
      const elapsedMinutes = Math.floor((now - startTime) / (1000 * 60));
      const labDurationMinutes = vm.lab.duration;

      // Check if the VM should have already been stopped
      if (elapsedMinutes >= labDurationMinutes) {
        logAutoStop('WARN', 'VM has exceeded lab duration, stopping immediately', {
          vmDatabaseId: vm.id,
          elapsedMinutes,
          labDurationMinutes
        });

        // Stop the VM immediately
        const userContext = {
          id: vm.user.id,
          username: vm.user.username,
          email: vm.user.email
        };
        
        executeAutoStop(vm.id, vm.lab, userContext);
        recoveredCount++;
      } else {
        // Schedule auto-stop for the remaining time
        const remainingMinutes = labDurationMinutes - elapsedMinutes;
        const userContext = {
          id: vm.user.id,
          username: vm.user.username,
          email: vm.user.email
        };

        const success = await scheduleLabAutoStop(
          vm.id, 
          vm.lab.id, 
          remainingMinutes, 
          userContext
        );

        if (success) {
          recoveredCount++;
          logAutoStop('INFO', 'Recovered auto-stop timer for VM', {
            vmDatabaseId: vm.id,
            elapsedMinutes,
            remainingMinutes,
            labDurationMinutes
          });
        } else {
          skippedCount++;
          logAutoStop('ERROR', 'Failed to recover auto-stop timer for VM', {
            vmDatabaseId: vm.id
          });
        }
      }
    }

    logAutoStop('INFO', 'Auto-stop timer recovery completed', {
      totalVMs: runningVMs.length,
      recovered: recoveredCount,
      skipped: skippedCount
    });

  } catch (error) {
    logAutoStop('ERROR', 'Failed during timer recovery', {
      error: error.message,
      stack: error.stack
    });
  }
}

/**
 * Cleanup function to clear all active timers (useful for graceful shutdown)
 */
function cleanupAllTimers() {
  logAutoStop('INFO', 'Cleaning up all active timers', {
    count: activeTimers.size
  });

  for (const [vmId, timer] of activeTimers.entries()) {
    clearTimeout(timer.timeoutId);
  }

  activeTimers.clear();
  logAutoStop('INFO', 'All auto-stop timers cleared');
}

/**
 * Health check function to verify service status
 * @returns {object} - Service health information
 */
function getServiceHealth() {
  const now = new Date();
  const activeTimersArray = getActiveTimers();
  
  return {
    status: 'healthy',
    activeTimersCount: activeTimersArray.length,
    memoryUsage: process.memoryUsage(),
    uptime: process.uptime(),
    timestamp: now.toISOString(),
    timers: activeTimersArray.map(timer => ({
      vmDatabaseId: timer.vmDatabaseId,
      labId: timer.labId,
      labName: timer.labName,
      username: timer.username,
      scheduledAt: timer.scheduledAt.toISOString(),
      stopTime: timer.stopTime.toISOString(),
      timeRemainingMs: timer.timeRemainingMs,
      timeRemainingHuman: `${Math.floor(timer.timeRemainingMs / (1000 * 60))} minutes`
    }))
  };
}

module.exports = {
  scheduleLabAutoStop,
  cancelLabAutoStop,
  getActiveTimers,
  recoverAutoStopTimers,
  cleanupAllTimers,
  getServiceHealth,
  logAutoStop
};
