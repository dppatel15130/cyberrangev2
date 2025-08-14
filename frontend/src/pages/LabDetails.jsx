import { useState, useEffect, useRef, useContext } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { Container, Row, Col, Card, Button, Badge, Alert, Spinner, ProgressBar, Modal, Form } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { AuthContext } from '../context/AuthContext';
import { 
  faFlask, 
  faPlay, 
  faArrowLeft, 
  faExclamationTriangle, 
  faCheckCircle, 
  faDesktop, 
  faStop,
  faSpinner,
  faClock,
  faListCheck,
  faClipboardCheck,
  faInfoCircle,
  faUserTie,
  faCalendarAlt,
  faLayerGroup,
  faTachometerAlt,
  faBook,
  faCheck,
  faFlag,
  faTrophy
} from '@fortawesome/free-solid-svg-icons';
import axios from '../utils/axiosConfig';

const LabDetails = () => {
  const { labId } = useParams();
  const navigate = useNavigate();
  const pollingIntervalRef = useRef(null);
  const timeoutRef = useRef(null);
  const { user } = useContext(AuthContext);
  
  const [lab, setLab] = useState({
    name: '',
    description: '',
    category: '',
    difficulty: 'beginner',
    instructions: '',
    flag: '',
    vmTemplateId: '',
    active: true,
    duration: 60,
    creator: { username: 'System' },
    createdAt: new Date(),
    updatedAt: new Date()
  });
  
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [vmStatus, setVmStatus] = useState({
    state: 'idle', // 'idle', 'starting', 'running', 'stopping', 'error'
    progress: 0,
    message: '',
    vmId: null,
    proxmoxVmId: null,
    guacamoleUrl: null,
    ipAddress: null,
    errorDetails: null
  });
  const [showEndLabModal, setShowEndLabModal] = useState(false);
  const [showFlagModal, setShowFlagModal] = useState(false);
  const [flagInput, setFlagInput] = useState('');
  const [flagResult, setFlagResult] = useState(null);
  const [submittingFlag, setSubmittingFlag] = useState(false);

  useEffect(() => {
    const fetchLabDetails = async () => {
      try {
        console.log('Fetching lab details for ID:', labId);
        const res = await axios.get(`/labs/${labId}`);
        
        // Process the lab data to ensure proper structure
        const processedLab = {
          ...res.data,
          // Ensure creator has a default value
          creator: res.data.creator || { username: 'System' }
        };
        
        console.log('Processed lab data:', {
          id: processedLab.id,
          name: processedLab.name,
          duration: processedLab.duration,
          hasCreator: !!processedLab.creator
        });
        
        setLab(processedLab);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching lab details:', {
          message: err.message,
          response: err.response?.data,
          status: err.response?.status
        });
        setError('Failed to load lab details. Please try again later.');
        setLoading(false);
      }
    };

    const checkExistingVM = async () => {
      try {
        console.log('Checking for existing VM for lab:', labId);
        const vmResponse = await axios.get(`/vms/lab/${labId}`);
        
        if (vmResponse.data && vmResponse.data.status === 'running') {
          console.log('Found existing running VM:', vmResponse.data);
          setVmStatus({
            state: 'running',
            progress: 100,
            message: 'Your lab is ready!',
            vmId: vmResponse.data.vmId,
            proxmoxVmId: vmResponse.data.proxmoxVmId,
            guacamoleUrl: vmResponse.data.guacamoleUrl,
            ipAddress: vmResponse.data.ipAddress,
            errorDetails: null
          });
        } else if (vmResponse.data && vmResponse.data.status) {
          console.log('Found VM with status:', vmResponse.data.status);
          setVmStatus(prev => ({
            ...prev,
            state: 'idle',
            vmId: vmResponse.data.vmId,
            proxmoxVmId: vmResponse.data.proxmoxVmId,
            ipAddress: vmResponse.data.ipAddress,
            guacamoleUrl: vmResponse.data.guacamoleUrl
          }));
        }
      } catch (err) {
        if (err.response?.status !== 404) {
          console.error('Error checking existing VM:', err.message);
        }
        // If no VM found (404) or other error, keep default idle state
      }
    };

    fetchLabDetails();
    checkExistingVM();
  }, [labId]);

  // Cleanup intervals on unmount
  useEffect(() => {
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const startPolling = (proxmoxVmId) => {
    // Clear any existing polling
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
    }

    let pollCount = 0;
    const maxPolls = 240; // 240 * 3 seconds = 12 minutes max
    let actualVmId = proxmoxVmId;

    const poll = async () => {
      pollCount++;
      try {
        console.log(`Polling VM status (attempt ${pollCount}/${maxPolls})...`);
        
        // Always try to get VM status using the lab endpoint first
        let statusResponse;
        try {
          statusResponse = await axios.get(`/vms/lab/${labId}`, {
            timeout: 10000
          });
          
          // If we got a response, update actualVmId and use this data
          if (statusResponse.data && statusResponse.data.proxmoxVmId) {
            actualVmId = statusResponse.data.proxmoxVmId;
            console.log('Found VM via lab endpoint:', actualVmId);
          }
        } catch (err) {
          // If lab endpoint fails, try the proxmox status endpoint as fallback
          if (actualVmId && actualVmId !== 'unknown') {
            console.log('Lab endpoint failed, falling back to proxmox status endpoint');
            try {
              statusResponse = await axios.get(`/vms/status/proxmox/${actualVmId}`, {
                timeout: 10000
              });
            } catch (proxmoxErr) {
              console.log('Both endpoints failed:', proxmoxErr.message);
              setVmStatus(prev => ({
                ...prev,
                message: 'Waiting for VM to be created...',
                progress: Math.min(prev.progress + 0.5, 25)
              }));
              return;
            }
          } else {
            console.log('No existing VM found yet, continuing to check...');
            setVmStatus(prev => ({
              ...prev,
              message: 'Checking for VM creation...',
              progress: Math.min(prev.progress + 1, 30)
            }));
            return;
          }
        }

        const status = statusResponse.data;
        console.log('VM Status Update:', status);

        // Update progress based on status and poll count
        let progress = 20 + Math.min(pollCount * 0.75, 45); // Start at 20%, increase more gradually
        
        // Adjust progress based on VM status
        switch (status.status) {
          case 'creating':
            progress = Math.max(progress, 25);
            break;
          case 'running':
            if (!status.ipAddress) {
              progress = Math.max(progress, 60); // VM running, waiting for IP
            } else if (!status.guacamoleUrl) {
              progress = Math.max(progress, 85); // IP available, setting up remote access
            } else {
              progress = 100; // Fully ready
            }
            break;
          case 'failed':
          case 'error':
            progress = 0;
            break;
          default:
            // Keep current progress calculation
            break;
        }

        setVmStatus(prev => ({
          ...prev,
          progress: Math.min(progress, 95), // Cap at 95% until fully ready
          message: getStatusMessage(status.status, status.ipAddress, status.guacamoleUrl),
          vmId: status.vmId,
          proxmoxVmId: status.proxmoxVmId,
          ipAddress: status.ipAddress,
          guacamoleUrl: status.guacamoleUrl,
          errorDetails: status.errorDetails
        }));

        // Check if VM is fully ready
        if (status.status === 'running' && status.guacamoleUrl) {
          setVmStatus(prev => ({
            ...prev,
            state: 'running',
            progress: 100,
            message: 'Your lab is ready!',
            vmId: status.vmId,
            proxmoxVmId: status.proxmoxVmId,
            ipAddress: status.ipAddress,
            guacamoleUrl: status.guacamoleUrl
          }));
          
          // Stop polling
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = null;
          
          if (timeoutRef.current) {
            clearTimeout(timeoutRef.current);
            timeoutRef.current = null;
          }
          
          return;
        }

        // Check if VM failed
        if (status.status === 'failed') {
          setVmStatus(prev => ({
            ...prev,
            state: 'error',
            progress: 0,
            message: status.errorDetails || 'VM failed to start',
            errorDetails: status.errorDetails
          }));
          
          // Stop polling
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = null;
          
          if (timeoutRef.current) {
            clearTimeout(timeoutRef.current);
            timeoutRef.current = null;
          }
          
          return;
        }

        // Stop polling after max attempts
        if (pollCount >= maxPolls) {
          setVmStatus(prev => ({
            ...prev,
            state: 'error',
            progress: 0,
            message: 'VM startup timed out. Please try again.',
            errorDetails: 'Timeout after 10 minutes'
          }));
          
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = null;
        }

      } catch (error) {
        console.error('Error polling VM status:', error);
        
        // Check if this is a network error or actual failure
        const isNetworkError = error.code === 'ECONNABORTED' || 
                               error.code === 'NETWORK_ERROR' ||
                               error.response?.status >= 500;
        
        // Only show error after multiple consecutive failures
        if (pollCount >= maxPolls || (!isNetworkError && pollCount > 10)) {
          const errorMessage = error.response?.data?.message || 
                               error.message || 
                               'Failed to check VM status. Please try again.';
          
          setVmStatus(prev => ({
            ...prev,
            state: 'error',
            progress: 0,
            message: errorMessage,
            errorDetails: error.response?.data?.error || error.message
          }));
          
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = null;
        } else {
          // Update status to show we're still trying despite errors
          setVmStatus(prev => ({
            ...prev,
            message: isNetworkError ? 
              'Connection issues, retrying...' : 
              `Checking VM status (attempt ${pollCount}/${maxPolls})...`,
            progress: Math.min(prev.progress + 1, 90) // Slow progress during errors
          }));
        }
      }
    };

    // Start polling every 3 seconds
    pollingIntervalRef.current = setInterval(poll, 3000);

    // Set overall timeout (10 minutes)
    timeoutRef.current = setTimeout(() => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
        
        setVmStatus(prev => ({
          ...prev,
          state: 'error',
          progress: 0,
          message: 'VM startup timed out. Please try again.',
          errorDetails: 'Overall timeout after 10 minutes'
        }));
      }
    }, 600000); // 10 minutes
  };

  const getStatusMessage = (status, ipAddress, guacamoleUrl) => {
    switch (status) {
      case 'creating':
        return 'Initializing virtual machine...';
      case 'running':
        if (!ipAddress) {
          return 'VM is booting, waiting for network configuration...';
        } else if (!guacamoleUrl) {
          return `VM is running (${ipAddress}), setting up remote access...`;
        } else {
          return 'Lab environment is ready!';
        }
      case 'failed':
      case 'error':
        return 'Failed to start lab environment';
      case 'not_found':
        return 'VM session not found';
      default:
        return 'Preparing lab environment...';
    }
  };

  const startLab = async () => {
    try {
      setVmStatus({
        state: 'starting',
        progress: 10,
        message: 'Starting your lab environment...',
        vmId: null,
        proxmoxVmId: null,
        guacamoleUrl: null,
        ipAddress: null,
        errorDetails: null
      });
      setError(null);
      
      console.log('Sending start lab request...');
      let res;
      try {
        res = await axios.post('/vms/start', { labId }, {
          timeout: 30000 // 30 second timeout for initial request
        });
      } catch (timeoutError) {
        console.warn('Initial start request timed out. Checking VM status in background.');
        setVmStatus(prev => ({
          ...prev,
          message: 'The VM may be starting, awaiting status confirmation...'
        }));
        // Begin polling for VM status even if start request seems to timeout
        startPolling('unknown'); // Pass a placeholder id to start polling
        return;
      }
      
      console.log('Start lab response:', res.data);

      // Check if this is a web lab that should redirect
      if (res.data.labType === 'web' && res.data.redirectTo) {
        console.log('Web lab detected, redirecting to:', res.data.redirectTo);
        navigate(res.data.redirectTo);
        return;
      }

      if (res.data.status === 'creating') {
        // VM creation started, begin polling
        setVmStatus(prev => ({
          ...prev,
          progress: 20,
          message: 'VM creation started, monitoring progress...',
          proxmoxVmId: res.data.vmId
        }));
        
        startPolling(res.data.vmId);
        
      } else if (res.data.status === 'running' && res.data.guacamoleUrl) {
        // VM already running and ready
        setVmStatus({
          state: 'running',
          progress: 100,
          message: 'Your lab is ready!',
          vmId: res.data.vmId,
          proxmoxVmId: res.data.vmId,
          guacamoleUrl: res.data.guacamoleUrl,
          ipAddress: res.data.ipAddress || null,
          errorDetails: null
        });
        
      } else {
        // Unexpected response
        throw new Error('Unexpected response from server: ' + JSON.stringify(res.data));
      }
      
    } catch (err) {
      console.error('Error starting lab:', err);
      
      let errorMessage = 'Failed to start lab. Please try again later.';
      
      if (err.code === 'ECONNABORTED') {
        errorMessage = 'Request timeout. The VM may be starting in the background. Please wait a moment and refresh the page.';
      } else if (err.response?.data?.message) {
        errorMessage = err.response.data.message;
      } else if (err.message) {
        errorMessage = err.message;
      }
      
      setVmStatus({
        state: 'error',
        progress: 0,
        message: errorMessage,
        vmId: null,
        proxmoxVmId: null,
        guacamoleUrl: null,
        ipAddress: null,
        errorDetails: err.response?.data?.error || err.message
      });
      setError(errorMessage);
    }
  };
  
  const stopLab = async () => {
    if (!vmStatus.vmId && !vmStatus.proxmoxVmId) return;
    
    try {
      setVmStatus(prev => ({
        ...prev,
        state: 'stopping',
        message: 'Stopping your lab environment...'
      }));
      
      // Stop any ongoing polling
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
      
      const vmIdToStop = vmStatus.vmId || vmStatus.proxmoxVmId;
      await axios.post(`/vms/${vmIdToStop}/stop`);
      
      setVmStatus({
        state: 'idle',
        progress: 0,
        message: '',
        vmId: null,
        proxmoxVmId: null,
        guacamoleUrl: null,
        ipAddress: null,
        errorDetails: null
      });
      setShowEndLabModal(false);
    } catch (err) {
      console.error('Error stopping lab:', err);
      setError('Failed to stop lab. Please try again.');
      
      // Revert state on error
      setVmStatus(prev => ({
        ...prev,
        state: prev.guacamoleUrl ? 'running' : 'idle',
        message: prev.guacamoleUrl ? 'Your lab is ready!' : ''
      }));
    }
  };
  
  const openLabInNewTab = () => {
    if (vmStatus.guacamoleUrl) {
      window.open(vmStatus.guacamoleUrl, '_blank', 'noopener,noreferrer');
    }
  };

  // Helper functions
  const getDifficultyBadgeVariant = (difficulty) => {
    const variants = {
      beginner: 'success',
      intermediate: 'warning',
      advanced: 'danger'
    };
    return variants[difficulty] || 'secondary';
  };

  const formatDuration = (minutes) => {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    if (hours > 0) {
      return `${hours}h ${mins}m`;
    }
    return `${mins} minutes`;
  };
  
  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const options = { 
      year: 'numeric', 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    };
    return new Date(dateString).toLocaleDateString(undefined, options);
  };

  const getDifficultyBadge = (difficulty) => {
    switch (difficulty) {
      case 'beginner':
        return <Badge bg="success">Beginner</Badge>;
      case 'intermediate':
        return <Badge bg="warning">Intermediate</Badge>;
      case 'advanced':
        return <Badge bg="danger">Advanced</Badge>;
      default:
        return <Badge bg="secondary">{difficulty}</Badge>;
    }
  };

  // Render loading state
  if (loading) {
    return (
      <Container className="py-5">
        <div className="text-center">
          <Spinner animation="border" variant="primary" />
          <p className="mt-3">Loading lab details...</p>
        </div>
      </Container>
    );
  }

  // Render VM status overlay only during starting, stopping, or error states
  const renderVmStatusOverlay = () => {
    if (vmStatus.state === 'idle' || vmStatus.state === 'running') return null;
    
    return (
      <div className="position-fixed top-0 start-0 w-100 h-100 bg-dark bg-opacity-75 d-flex flex-column justify-content-center align-items-center" style={{ zIndex: 1050 }}>
        <div className="bg-dark p-4 rounded-3 shadow-lg text-center" style={{ width: '90%', maxWidth: '500px' }}>
          {vmStatus.state === 'starting' && (
            <>
              <Spinner animation="border" variant="primary" className="mb-3" />
              <h4 className="text-white mb-3">Preparing Your Lab</h4>
              <p className="text-light mb-3">{vmStatus.message}</p>
              <ProgressBar now={vmStatus.progress} label={`${vmStatus.progress}%`} className="mb-3" animated />
              {vmStatus.ipAddress && (
                <p className="text-info small">VM IP: {vmStatus.ipAddress}</p>
              )}
              <p className="text-muted small">This may take up to 5 minutes...</p>
            </>
          )}
          
          {vmStatus.state === 'running' && (
            <>
              <div className="text-success mb-3">
                <FontAwesomeIcon icon={faCheckCircle} size="3x" />
              </div>
              <h4 className="text-white mb-3">Lab Ready!</h4>
              <p className="text-light mb-4">Your lab environment is now ready to use.</p>
              {vmStatus.ipAddress && (
                <p className="text-info small mb-3">VM IP: {vmStatus.ipAddress}</p>
              )}
              <div className="d-grid gap-2">
                <Button variant="success" size="lg" onClick={openLabInNewTab}>
                  <FontAwesomeIcon icon={faDesktop} className="me-2" />
                  Open Lab
                </Button>
                <Button variant="outline-light" onClick={() => setShowEndLabModal(true)}>
                  <FontAwesomeIcon icon={faStop} className="me-2" />
                  End Lab Session
                </Button>
              </div>
            </>
          )}
          
          {vmStatus.state === 'stopping' && (
            <>
              <Spinner animation="border" variant="light" className="mb-3" />
              <h4 className="text-white mb-3">Stopping Lab</h4>
              <p className="text-light">Please wait while we clean up your lab environment...</p>
            </>
          )}
          
          {vmStatus.state === 'error' && (
            <>
              <div className="text-danger mb-3">
                <FontAwesomeIcon icon={faExclamationTriangle} size="3x" />
              </div>
              <h4 className="text-white mb-3">Something Went Wrong</h4>
              <p className="text-light mb-2">{vmStatus.message}</p>
              {vmStatus.errorDetails && (
                <p className="text-muted small mb-4">Details: {vmStatus.errorDetails}</p>
              )}
              <div className="d-grid gap-2">
                <Button variant="primary" onClick={startLab}>
                  <FontAwesomeIcon icon={faPlay} className="me-2" />
                  Try Again
                </Button>
                <Button variant="outline-light" onClick={() => setVmStatus(prev => ({ ...prev, state: 'idle' }))}>
                  Close
                </Button>
              </div>
            </>
          )}
        </div>
      </div>
    );
  };

  if (!lab) {
    return (
      <Container className="py-4">
        <div className="d-flex justify-content-between align-items-start mb-4">
          <div>
            <h1 className="mb-1">
              <FontAwesomeIcon icon={faFlask} className="me-2" />
              {lab.name}
            </h1>
            <div className="d-flex align-items-center gap-2">
              <Badge bg={getDifficultyBadgeVariant(lab.difficulty)} className="text-capitalize">
                {lab.difficulty}
              </Badge>
              <span className="text-muted">
                <FontAwesomeIcon icon={faClock} className="me-1" />
                {formatDuration(lab.duration || 60)}
              </span>
              {lab.category && (
                <span className="text-muted">
                  <FontAwesomeIcon icon={faLayerGroup} className="me-1" />
                  {lab.category}
                </span>
              )}
            </div>
          </div>
          <Button as={Link} to="/labs" variant="outline-secondary">
            <FontAwesomeIcon icon={faArrowLeft} className="me-2" />
            Back to Labs
          </Button>
        </div>
      </Container>
    );
  }

  return (
    <Container className="py-4 position-relative">
      {renderVmStatusOverlay()}
      
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <Button as={Link} to="/dashboard" variant="outline-secondary" size="sm" className="mb-2">
            <FontAwesomeIcon icon={faArrowLeft} className="me-2" />
            Back to Dashboard
          </Button>
          <h1 className="mb-0">
            <FontAwesomeIcon icon={faFlask} className="me-2" />
            {lab.name}
          </h1>
        </div>
        
        {vmStatus.state === 'idle' ? (
          <Button 
            variant="primary" 
            size="lg"
            onClick={startLab}
            disabled={vmStatus.state !== 'idle'}
          >
            <FontAwesomeIcon icon={faPlay} className="me-2" />
            Start Lab
          </Button>
        ) : (
          <div className="d-flex gap-2">
            {vmStatus.state === 'running' && (
              <Button 
                variant="success" 
                onClick={openLabInNewTab}
                className="me-2"
              >
                <FontAwesomeIcon icon={faDesktop} className="me-2" />
                Open Lab
              </Button>
            )}
            <Button 
              variant="danger" 
              onClick={() => setShowEndLabModal(true)}
              disabled={vmStatus.state === 'stopping'}
            >
              {vmStatus.state === 'stopping' ? (
                <>
                  <FontAwesomeIcon icon={faSpinner} spin className="me-2" />
                  Stopping...
                </>
              ) : (
                <>
                  <FontAwesomeIcon icon={faStop} className="me-2" />
                  End Lab
                </>
              )}
            </Button>
          </div>
        )}
      </div>

      {error && (
        <Alert variant="danger" className="mb-4" dismissible onClose={() => setError(null)}>
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      <Row>
        <Col lg={8}>
          <Card className="mb-4 shadow-sm">
            <Card.Body>
              <div className="mb-4">
                <h4 className="mb-1">Lab Overview</h4>
                <p className="text-muted">{lab.description || 'No description provided.'}</p>
              </div>

              <div className="mb-4">
                <h5 className="d-flex align-items-center mb-3">
                  <FontAwesomeIcon icon={faBook} className="me-2 text-primary" />
                  Instructions
                </h5>
                <div className="bg-light p-3 rounded">
                  {lab.instructions ? (
                    <div style={{ whiteSpace: 'pre-line' }}>{lab.instructions}</div>
                  ) : (
                    <p className="text-muted mb-0">No instructions provided.</p>
                  )}
                </div>
              </div>

              <div className="lab-actions mb-4">
                {vmStatus.state === 'idle' && (
                  <div className="text-center p-4 border rounded bg-light">
                    <h5>Ready to start the lab?</h5>
                    <p className="text-muted mb-4">Click the button below to launch your lab environment.</p>
                    <Button
                      variant="primary"
                      size="lg"
                      onClick={startLab}
                      className="mb-2"
                    >
                      <FontAwesomeIcon icon={faPlay} className="me-2" />
                      Start Lab
                    </Button>
                    <p className="text-muted small mb-0">
                      Starting your lab may take a few moments. Please be patient.
                    </p>
                  </div>
                )}

                {vmStatus.state === 'running' && (
                  <div className="p-4 border rounded bg-light">
                    <div className="d-flex justify-content-between align-items-center mb-3">
                      <h5 className="text-success mb-0">
                        <FontAwesomeIcon icon={faCheckCircle} className="me-2" />
                        Lab Session Active
                      </h5>
                      <Badge bg="success" pill>Running</Badge>
                    </div>
                    <p className="mb-3">Your lab environment is ready to use. Click the button below to access the lab.</p>
                    {vmStatus.ipAddress && (
                      <p className="text-muted small mb-3">VM IP Address: <code>{vmStatus.ipAddress}</code></p>
                    )}
                    
                    {/* Login Instructions */}
                    <div className="alert alert-info small mb-3">
                      <strong><FontAwesomeIcon icon={faInfoCircle} className="me-1" />Login Instructions:</strong>
                      <br />After clicking "Open Lab Environment", please login with:
                      <br />• <strong>Username:</strong> {user?.username || 'your_username'}
                      <br />• <strong>Password:</strong> sac@1234
                    </div>
                    
                    <div className="d-flex gap-2 mb-3">
                      <Button variant="success" onClick={openLabInNewTab} className="flex-grow-1">
                        <FontAwesomeIcon icon={faDesktop} className="me-2" />
                        Open Lab Environment
                      </Button>
                      <Button 
                        variant="outline-danger" 
                        onClick={() => setShowEndLabModal(true)}
                        className="flex-grow-1"
                      >
                        <FontAwesomeIcon icon={faStop} className="me-2" />
                        End Lab
                      </Button>
                    </div>
                    <div className="d-grid">
                      <Button 
                        variant="primary" 
                        onClick={() => setShowFlagModal(true)}
                      >
                        <FontAwesomeIcon icon={faFlag} className="me-2" />
                        Submit Flag
                      </Button>
                    </div>
                  </div>
                )}

                {vmStatus.state === 'starting' && (
                  <div className="p-4 border rounded bg-primary bg-opacity-10">
                    <div className="d-flex justify-content-between align-items-center mb-3">
                      <h5 className="text-primary mb-0">
                        <FontAwesomeIcon icon={faSpinner} spin className="me-2" />
                        Starting Lab Environment
                      </h5>
                      <Badge bg="primary" pill>Starting</Badge>
                    </div>
                    <p className="mb-3">{vmStatus.message}</p>
                    <ProgressBar now={vmStatus.progress} label={`${vmStatus.progress}%`} animated className="mb-3" />
                    {vmStatus.ipAddress && (
                      <p className="text-info small">VM IP: {vmStatus.ipAddress}</p>
                    )}
                    <p className="text-muted small mb-0">
                      This process may take up to 5 minutes. Please don't refresh the page.
                    </p>
                  </div>
                )}

                {vmStatus.state === 'error' && (
                  <div className="p-4 border rounded bg-danger bg-opacity-10">
                    <div className="d-flex justify-content-between align-items-center mb-3">
                      <h5 className="text-danger mb-0">
                        <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
                        Lab Start Failed
                      </h5>
                      <Badge bg="danger" pill>Error</Badge>
                    </div>
                    <p className="mb-3">{vmStatus.message}</p>
                    {vmStatus.errorDetails && (
                      <div className="bg-light p-2 rounded mb-3">
                        <small className="text-muted">Technical details: {vmStatus.errorDetails}</small>
                      </div>
                    )}
                    <Button variant="primary" onClick={startLab}>
                      <FontAwesomeIcon icon={faPlay} className="me-2" />
                      Try Again
                    </Button>
                  </div>
                )}
                  <p className="text-muted">
                    Please submit the flag in the format <code>flag{'{'} your_flag_here {'}'}</code>.
                  </p>
              </div>
            </Card.Body>
          </Card>
        </Col>

        <Col lg={4}>
          <Card className="mb-4 shadow-sm">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center mb-3">
                <h5 className="mb-0 d-flex align-items-center">
                  <FontAwesomeIcon icon={faInfoCircle} className="me-2 text-primary" />
                  Lab Information
                </h5>
                {vmStatus.state === 'running' && (
                  <Badge bg="success" pill>Active</Badge>
                )}
                {vmStatus.state === 'starting' && (
                  <Badge bg="primary" pill>Starting</Badge>
                )}
              </div>
              <div className="list-group list-group-flush">
                <div className="list-group-item px-0 py-2 border-0">
                  <div className="d-flex justify-content-between">
                    <span className="text-muted">
                      <FontAwesomeIcon icon={faLayerGroup} className="me-2" />
                      Category:
                    </span>
                    <span className="fw-medium text-capitalize">{lab.category || 'N/A'}</span>
                  </div>
                </div>
                <div className="list-group-item px-0 py-2 border-0">
                  <div className="d-flex justify-content-between">
                    <span className="text-muted">
                      <FontAwesomeIcon icon={faUserTie} className="me-2" />
                      Created By:
                    </span>
                    <span className="fw-medium">{lab.creator?.username || 'System'}</span>
                  </div>
                </div>
                <div className="list-group-item px-0 py-2 border-0">
                  <div className="d-flex justify-content-between">
                    <span className="text-muted">
                      <FontAwesomeIcon icon={faCalendarAlt} className="me-2" />
                      Created:
                    </span>
                    <span className="fw-medium">
                      {formatDate(lab.createdAt)}
                    </span>
                  </div>
                </div>
                <div className="list-group-item px-0 py-2 border-0">
                  <div className="d-flex justify-content-between">
                    <span className="text-muted">
                      <FontAwesomeIcon icon={faCalendarAlt} className="me-2" />
                      Last Updated:
                    </span>
                    <span className="fw-medium">
                      {formatDate(lab.updatedAt)}
                    </span>
                  </div>
                </div>
                <div className="list-group-item px-0 py-2 border-0">
                  <div className="d-flex justify-content-between">
                    <span className="text-muted">
                      <FontAwesomeIcon icon={faClock} className="me-2" />
                      Duration:
                    </span>
                    <span className="fw-medium">
                      {formatDuration(lab.duration || 60)}
                    </span>
                  </div>
                </div>
                <div className="list-group-item px-0 py-2 border-0">
                  <div className="d-flex justify-content-between">
                    <span className="text-muted">
                      <FontAwesomeIcon icon={faTachometerAlt} className="me-2" />
                      Difficulty:
                    </span>
                    <Badge bg={getDifficultyBadgeVariant(lab.difficulty)} className="text-capitalize">
                      {lab.difficulty}
                    </Badge>
                  </div>
                </div>
                <div className="list-group-item px-0 pt-2 border-0">
                  <div className="d-flex justify-content-between">
                    <span className="text-muted">
                      <FontAwesomeIcon icon={faTrophy} className="me-2" />
                      Points:
                    </span>
                    <span className="fw-medium text-success">
                      {lab.points || 100} points
                    </span>
                  </div>
                </div>
              </div>
            </Card.Body>
          </Card>

          {vmStatus.state === 'running' && (
            <Card className="border-warning shadow-sm mt-4">
              <Card.Body className="bg-warning bg-opacity-10">
                <div className="d-flex align-items-center mb-2">
                  <FontAwesomeIcon icon={faExclamationTriangle} className="text-warning me-2" />
                  <h6 className="text-warning mb-0">Active Lab Session</h6>
                </div>
                <p className="small mb-3">
                  Your lab environment is currently running. Don't forget to end your session when you're done to free up resources.
                </p>
                <Button
                  variant="outline-warning"
                  size="sm"
                  className="w-100"
                  onClick={() => setShowEndLabModal(true)}
                >
                  <FontAwesomeIcon icon={faStop} className="me-2" />
                  End Lab Session
                </Button>
              </Card.Body>
            </Card>
          )}
        </Col>
      </Row>

      {/* Flag Submission Modal */}
      <Modal show={showFlagModal} onHide={() => setShowFlagModal(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Submit Flag</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form id="flag-form" onSubmit={async (e) => {
            e.preventDefault();
            setSubmittingFlag(true);
            setFlagResult(null);
            
            try {
              const response = await axios.post('/flags/submit', {
                labId: labId,
                flag: flagInput
              });
              
              if (response.data.success && response.data.correct) {
                setFlagResult({
                  success: true,
                  message: `🎉 Congratulations! You captured the flag and earned ${response.data.pointsAwarded} points! 🎉\nYour total points: ${response.data.totalPoints}`,
                  points: response.data.pointsAwarded,
                  totalPoints: response.data.totalPoints
                });
                
                // Update the lab object to reflect completion
                setLab(prev => ({
                  ...prev,
                  completed: true,
                  pointsEarned: response.data.pointsAwarded
                }));
              } else {
                setFlagResult({
                  success: false,
                  message: response.data.message || 'Incorrect flag. Try again!'
                });
              }
            } catch (err) {
              console.error('Error submitting flag:', err);
              const errorMessage = err.response?.data?.message || 'Error submitting flag. Please try again.';
              setFlagResult({
                success: false,
                message: errorMessage
              });
            } finally {
              setSubmittingFlag(false);
            }
          }}>
            <Form.Group className="mb-3">
              <Form.Label>Enter the flag you found:</Form.Label>
              <Form.Control
                type="text"
                placeholder="flag{your_flag_here}"
                value={flagInput}
                onChange={(e) => setFlagInput(e.target.value)}
                autoFocus
              />
              <Form.Text className="text-muted">
                Please submit the flag in the format: <code>flag{'{'} your_flag_here {'}'}</code>
              </Form.Text>
            </Form.Group>
            {flagResult && 
              <Alert variant={flagResult.success ? 'success' : 'danger'}>
                {flagResult.message}
              </Alert>}
          </Form>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowFlagModal(false)} disabled={submittingFlag}>
            Close
          </Button>
          <Button 
            variant="primary" 
            type="submit" 
            form="flag-form"
            disabled={!flagInput || submittingFlag}
          >
            {submittingFlag ? (
              <>
                <FontAwesomeIcon icon={faSpinner} spin className="me-2" />
                Submitting...
              </>
            ) : (
              <>
                <FontAwesomeIcon icon={faFlag} className="me-2" />
                Submit Flag
              </>
            )}
          </Button>
        </Modal.Footer>
      </Modal>

      {/* End Lab Confirmation Modal */}
      <Modal show={showEndLabModal} onHide={() => setShowEndLabModal(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>End Lab Session</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>Before ending your lab session, would you like to submit a flag?</p>
          <p className="text-muted small">
            If you found the flag during this lab, you can submit it below. Otherwise, you can skip and end the session directly.
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowEndLabModal(false)}>
            Cancel
          </Button>
          <Button 
            variant="primary" 
            onClick={() => {
              setShowEndLabModal(false);
              setShowFlagModal(true);
            }}
            className="me-2"
          >
            <FontAwesomeIcon icon={faFlag} className="me-2" />
            Submit Flag
          </Button>
          <Button variant="danger" onClick={stopLab}>
            {vmStatus.state === 'stopping' ? (
              <>
                <FontAwesomeIcon icon={faSpinner} spin className="me-2" />
                Stopping...
              </>
            ) : (
              'End Without Flag'
            )}
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
};

export default LabDetails;