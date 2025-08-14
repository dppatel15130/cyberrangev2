/**
 * Retrieves VM information by lab ID for the current user.
 * @param {object} req The Express request object.
 * @param {object} res The Express response object.
 */
exports.getVMByLabId = async (req, res) => {
  try {
    const { labId } = req.params;
    const userId = req.user.id;

    if (!labId) {
      return res.status(400).json({ message: 'Lab ID is required.' });
    }

    console.log(`[INFO] Retrieving VM for lab ${labId} and user ${userId}`);

    const vmRecord = await VM.findOne({
      where: {
        labId: labId,
        userId: userId
      }
    });

    if (!vmRecord) {
      return res.status(404).json({ message: 'No VM found for this lab.', status: 'not_found' });
    }

    res.json({
      vmId: vmRecord.vmId,
      proxmoxVmId: vmRecord.vmId,
      status: vmRecord.status,
      ipAddress: vmRecord.ipAddress,
      guacamoleUrl: vmRecord.guacamoleConnectionId ?
        guacamoleApi.getConnectionUrl(vmRecord.guacamoleConnectionId) : null
    });
  } catch (error) {
    console.error('Error retrieving VM by lab ID:', error.message);
    res.status(500).json({ message: 'Failed to retrieve VM.', error: error.message });
  }
};
