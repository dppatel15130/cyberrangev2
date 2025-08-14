import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Container, Row, Col, Card, Alert, Spinner, Button, Tabs, Tab, Badge, Form } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faArrowLeft, 
  faCheckCircle, 
  faTimesCircle, 
  faInfoCircle,
  faCode,
  faFlagCheckered,
  faExternalLinkAlt
} from '@fortawesome/free-solid-svg-icons';
import axios from '../utils/axiosConfig';

const WebLabView = () => {
  const { labId } = useParams();
  const navigate = useNavigate();
  const iframeRef = useRef(null);
  const [loading, setLoading] = useState(true);
  const [lab, setLab] = useState(null);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('instructions');
  const [submissionStatus, setSubmissionStatus] = useState({
    loading: false,
    success: null,
    message: ''
  });
  const [flag, setFlag] = useState('');
  const [isCompleted, setIsCompleted] = useState(false);
  
  // Polling for completion status
  const [polling, setPolling] = useState(false);
  const pollingInterval = useRef(null);
  
  // Fetch lab data
  useEffect(() => {
    const fetchLab = async () => {
      try {
        setLoading(true);
        const res = await axios.get(`/weblabs/${labId}`);
        setLab(res.data);
        setIsCompleted(!!res.data.completed);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching web lab:', err);
        setError('Failed to load web lab. Please try again later.');
        setLoading(false);
      }
    };
    
    fetchLab();
    
    // Cleanup function
    return () => {
      if (pollingInterval.current) {
        clearInterval(pollingInterval.current);
      }
    };
  }, [labId]);
  
  // Handle messages from iframe
  useEffect(() => {
    const handleMessage = (event) => {
      // Verify origin if needed
      // if (lab?.webLab?.allowedOrigins && lab.webLab.allowedOrigins.length > 0) {
      //   const origin = new URL(event.origin).hostname;
      //   if (!lab.webLab.allowedOrigins.includes(origin)) return;
      // }
      
      if (event.data?.type === 'WEB_LAB_HEADERS') {
        handleHeaderCheck(event.data.headers);
      } else if (event.data?.type === 'header_status') {
        // Handle header status from iframe
        handleHeaderCheck(event.data.headers);
      } else if (event.data?.type === 'LAB_COMPLETED') {
        // Handle direct completion message from lab
        console.log('Received LAB_COMPLETED message:', event.data);
        handleLabCompletion(event.data.labId || labId);
      }
    };
    
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [lab, labId]);
  
  // Start/stop polling based on active tab and completion status
  useEffect(() => {
    if (activeTab === 'lab' && !isCompleted) {
      if (lab?.webLabData?.validationType === 'header_check') {
        startPolling();
      } else if (lab?.webLabData?.validationType === 'callback' || lab?.webLabData?.hostedUrl) {
        // For callback validation or external labs, poll the status endpoint
        startStatusPolling();
        
        // Also check for completion immediately when tab is activated
        if (iframeRef.current) {
          iframeRef.current.contentWindow.postMessage({ type: 'CHECK_COMPLETION' }, '*');
        }
      }
    } else {
      stopPolling();
      stopStatusPolling();
    }
    
    return () => {
      stopPolling();
      stopStatusPolling();
    };
  }, [activeTab, isCompleted, lab?.webLabData?.validationType, lab?.webLabData?.hostedUrl]);
  
  const startPolling = () => {
    if (pollingInterval.current) return;
    
    setPolling(true);
    pollingInterval.current = setInterval(() => {
      // Request headers from the iframe
      if (iframeRef.current) {
        iframeRef.current.contentWindow.postMessage({ type: 'GET_WEB_LAB_HEADERS' }, '*');
      }
    }, 2000); // Poll every 2 seconds
  };
  
  const stopPolling = () => {
    if (pollingInterval.current) {
      clearInterval(pollingInterval.current);
      pollingInterval.current = null;
    }
    setPolling(false);
  };

  // Status polling for callback validation or external labs
  const [statusPolling, setStatusPolling] = useState(false);
  const statusPollingInterval = useRef(null);

  const startStatusPolling = () => {
    if (statusPollingInterval.current) return;
    
    setStatusPolling(true);
    statusPollingInterval.current = setInterval(async () => {
      try {
        const res = await axios.get(`/weblabs/${labId}/status`);
        if (res.data.completed) {
          setIsCompleted(true);
          stopStatusPolling();
          setSubmissionStatus({
            loading: false,
            success: true,
            message: 'Congratulations! You have successfully completed the lab.'
          });
        }
      } catch (err) {
        console.error('Error checking lab status:', err);
        // Don't show error to user for polling failures
      }
    }, 5000); // Poll every 5 seconds
  };
  
  const stopStatusPolling = () => {
    if (statusPollingInterval.current) {
      clearInterval(statusPollingInterval.current);
      statusPollingInterval.current = null;
    }
    setStatusPolling(false);
  };
  
  const handleHeaderCheck = async (headers) => {
    if (!headers || isCompleted) return;
    
    try {
      const res = await axios.post(`/weblabs/${labId}/submit`, { headers });
      if (res.data.success) {
        setIsCompleted(true);
        stopPolling();
        setSubmissionStatus({
          loading: false,
          success: true,
          message: res.data.message
        });
      }
    } catch (err) {
      console.error('Error checking headers:', err);
      // Don't show error to user for polling failures
    }
  };
  
  // Handle direct lab completion
  const handleLabCompletion = async (completedLabId) => {
    if (isCompleted || completedLabId !== labId) return;
    
    try {
      console.log('Handling lab completion for lab ID:', completedLabId);
      const res = await axios.post(`/weblabs/${labId}/complete`);
      if (res.data.success) {
        setIsCompleted(true);
        stopPolling();
        stopStatusPolling();
        setSubmissionStatus({
          loading: false,
          success: true,
          message: 'Congratulations! You have successfully completed the lab.'
        });
      }
    } catch (err) {
      console.error('Error marking lab as completed:', err);
      // Try the submit endpoint as fallback
      try {
        const fallbackRes = await axios.post(`/weblabs/${labId}/submit`, { 
          headers: { 'Lab-Status': 'Completed' } 
        });
        if (fallbackRes.data.success) {
          setIsCompleted(true);
          stopPolling();
          stopStatusPolling();
          setSubmissionStatus({
            loading: false,
            success: true,
            message: fallbackRes.data.message || 'Lab completed successfully!'
          });
        }
      } catch (fallbackErr) {
        console.error('Fallback completion also failed:', fallbackErr);
      }
    }
  };
  
  const handleFlagSubmit = async (e) => {
    e.preventDefault();
    if (!flag.trim()) return;
    
    setSubmissionStatus({ loading: true, success: null, message: '' });
    
    try {
      const res = await axios.post(`/weblabs/${labId}/submit`, { flag });
      setIsCompleted(res.data.success);
      setSubmissionStatus({
        loading: false,
        success: res.data.success,
        message: res.data.message
      });
      
      if (res.data.success) {
        setFlag('');
      }
    } catch (err) {
      console.error('Error submitting flag:', err);
      setSubmissionStatus({
        loading: false,
        success: false,
        message: err.response?.data?.message || 'Failed to submit flag. Please try again.'
      });
    }
  };
  
  
  const renderStatusBadge = () => {
    if (isCompleted) {
      return (
        <Badge bg="success" className="ms-2">
          <FontAwesomeIcon icon={faCheckCircle} className="me-1" />
          Completed
        </Badge>
      );
    }
    return (
      <Badge bg="secondary" className="ms-2">
        <FontAwesomeIcon icon={faTimesCircle} className="me-1" />
        In Progress
      </Badge>
    );
  };
  
  if (loading) {
    return (
      <Container className="mt-5 text-center">
        <Spinner animation="border" role="status">
          <span className="visually-hidden">Loading...</span>
        </Spinner>
        <p className="mt-2">Loading web lab...</p>
      </Container>
    );
  }
  
  if (error || !lab) {
    return (
      <Container className="mt-5">
        <Alert variant="danger">
          <FontAwesomeIcon icon={faTimesCircle} className="me-2" />
          {error || 'Web lab not found'}
        </Alert>
        <Button 
          variant="outline-primary" 
          className="mt-3" 
          onClick={() => navigate(-1)}
        >
          <FontAwesomeIcon icon={faArrowLeft} className="me-2" />
          Back to Labs
        </Button>
      </Container>
    );
  }
  
  return (
    <Container className="mt-4">
      <Button 
        variant="outline-secondary" 
        className="mb-4" 
        onClick={() => navigate(-1)}
      >
        <FontAwesomeIcon icon={faArrowLeft} className="me-2" />
        Back to Labs
      </Button>
      
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>
          {lab.name}
          {renderStatusBadge()}
        </h2>
        <Badge bg={getDifficultyBadgeColor(lab.difficulty)}>
          {lab.difficulty.charAt(0).toUpperCase() + lab.difficulty.slice(1)}
        </Badge>
      </div>
      
      <Tabs
        activeKey={activeTab}
        onSelect={(k) => setActiveTab(k)}
        className="mb-3"
      >
        <Tab eventKey="instructions" title={
          <>
            <FontAwesomeIcon icon={faInfoCircle} className="me-1" />
            Instructions
          </>
        }>
          <Card className="mt-3">
            <Card.Body>
              <div className="mb-4">
                <h5>Description</h5>
                <p className="text-muted">{lab.description}</p>
              </div>
              
              <div className="mb-4">
                <h5>Instructions</h5>
                <div 
                  className="instructions-content" 
                  dangerouslySetInnerHTML={{ 
                    __html: formatInstructions(lab.instructions) 
                  }} 
                />
              </div>
              
              <div className="alert alert-info">
                <FontAwesomeIcon icon={faInfoCircle} className="me-2" />
                {lab.webLabData.validationType === 'header_check' 
                  ? 'This lab will be automatically completed when the required HTTP header is detected.'
                  : 'Submit the flag you find in the lab to complete this challenge.'}
              </div>
              
              <div className="d-flex justify-content-between mt-4">
                <div>
                  <strong>Category:</strong> {lab.category}
                </div>
                <div>
                  <strong>Points:</strong> {lab.points}
                </div>
              </div>
            </Card.Body>
          </Card>
        </Tab>
        
        <Tab 
          eventKey="lab" 
          title={
            <>
              <FontAwesomeIcon icon={faCode} className="me-1" />
              Lab
            </>
          }
          disabled={!lab.isActive}
        >
          <Card className="mt-3">
            <Card.Body>
              {!lab.isActive ? (
                <Alert variant="warning">
                  This lab is currently inactive. Please check back later.
                </Alert>
              ) : (
                <>
                  {lab.webLabData.validationType === 'header_check' && (
                    <div className="mb-3">
                      <div className="d-flex align-items-center mb-2">
                        <div className="me-2">
                          {isCompleted ? (
                            <FontAwesomeIcon icon={faCheckCircle} className="text-success" />
                          ) : polling ? (
                            <Spinner animation="border" size="sm" className="me-1" />
                          ) : (
                            <FontAwesomeIcon icon={faTimesCircle} className="text-danger" />
                          )}
                        </div>
                        <div>
                          {isCompleted 
                            ? 'Lab completed successfully!'
                            : polling 
                              ? 'Monitoring for completion...'
                              : 'Lab not yet completed'}
                        </div>
                      </div>
                    </div>
                  )}
                  
                  {lab.webLabData.hostedUrl ? (
                    <div className="mb-4">
                      <Button
                        variant="primary"
                        size="lg"
                        onClick={() => {
                          // Get the authentication token
                          const token = localStorage.getItem('token');
                          
                          // Try to open the external lab directly if the hostedUrl is available
                          // This avoids potential redirect issues with the status-check endpoint
                          if (lab.webLabData.hostedUrl) {
                            // Replace any placeholders in the URL
                            let url = lab.webLabData.hostedUrl.replace(/{{LAB_ID}}/g, labId);
                            
                            // Append the labId and token as query parameters
                            url += (url.includes('?') ? '&' : '?') + `labId=${labId}`;
                            if (token) {
                              url += `&token=${token}`;
                            }
                            
                            const win = window.open(url, '_blank');
                            if (win) {
                              win.focus();
                            } else {
                              alert('Please allow popups for this site to open the external lab.');
                            }
                          } else {
                            // Fallback to the status-check endpoint if hostedUrl is not available
                            let url = `/api/weblabs/status-check/${labId}`;
                            if (token) {
                              url += `?token=${token}`;
                            }
                            
                            const win = window.open(url, '_blank');
                            if (win) {
                              win.focus();
                            } else {
                              alert('Please allow popups for this site to open the external lab.');
                            }
                          }
                        }}
                        className="w-100 py-3"
                      >
                        <FontAwesomeIcon icon={faExternalLinkAlt} className="me-2" />
                        Open External Lab in New Window
                      </Button>
                      <div className="mt-3 text-center text-muted">
                        {statusPolling ? (
                          <div className="d-flex align-items-center justify-content-center">
                            <Spinner animation="border" size="sm" className="me-2" />
                            Checking completion status...
                          </div>
                        ) : isCompleted ? (
                          <div className="text-success">
                            <FontAwesomeIcon icon={faCheckCircle} className="me-2" />
                            Lab completed successfully!
                          </div>
                        ) : (
                          <div>
                            Complete the lab in the new window. This page will automatically update when you're done.
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="lab-container" style={{ position: 'relative', paddingBottom: '56.25%', height: 0, overflow: 'hidden' }}>
                      <iframe
                        ref={iframeRef}
                        srcDoc={lab.webLabData.htmlContent}
                        title="Web Lab"
                        style={{
                          position: 'absolute',
                          top: 0,
                          left: 0,
                          width: '100%',
                          height: '100%',
                          border: '1px solid #ddd',
                          borderRadius: '0.25rem',
                          backgroundColor: '#fff'
                        }}
                        sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-modals"
                      />
                    </div>
                  )}
                  
                  {lab.webLabData.validationType === 'input_flag' && (
                    <Card className="mt-3">
                      <Card.Body>
                        <h5 className="mb-3">
                          <FontAwesomeIcon icon={faFlagCheckered} className="me-2" />
                          Submit Flag
                        </h5>
                        
                        {submissionStatus.message && (
                          <Alert 
                            variant={submissionStatus.success ? 'success' : 'danger'}
                            className="mt-2"
                          >
                            {submissionStatus.message}
                          </Alert>
                        )}
                        
                        {!isCompleted && (
                          <Form onSubmit={handleFlagSubmit} className="mt-3">
                            <div className="input-group">
                              <Form.Control
                                type="text"
                                placeholder="Enter flag..."
                                value={flag}
                                onChange={(e) => setFlag(e.target.value)}
                                disabled={submissionStatus.loading}
                              />
                              <Button 
                                type="submit" 
                                variant="primary"
                                disabled={!flag.trim() || submissionStatus.loading}
                              >
                                {submissionStatus.loading ? (
                                  <>
                                    <Spinner
                                      as="span"
                                      animation="border"
                                      size="sm"
                                      role="status"
                                      aria-hidden="true"
                                      className="me-2"
                                    />
                                    Submitting...
                                  </>
                                ) : 'Submit Flag'}
                              </Button>
                            </div>
                          </Form>
                        )}
                      </Card.Body>
                    </Card>
                  )}
                  
                  {lab.webLabData.validationType === 'callback' && !isCompleted && (
                    <Card className="mt-3">
                      <Card.Body>
                        <h5 className="mb-3">
                          <FontAwesomeIcon icon={faCheckCircle} className="me-2" />
                          Manual Completion
                        </h5>
                        <p className="text-muted">If you've completed the lab but it hasn't been automatically detected, you can manually mark it as complete.</p>
                        <Button 
                          variant="primary"
                          onClick={() => handleLabCompletion(labId)}
                          disabled={submissionStatus.loading}
                        >
                          {submissionStatus.loading ? (
                            <>
                              <Spinner
                                as="span"
                                animation="border"
                                size="sm"
                                role="status"
                                aria-hidden="true"
                                className="me-2"
                              />
                              Processing...
                            </>
                          ) : 'Mark as Completed'}
                        </Button>
                      </Card.Body>
                    </Card>
                  )}
                </>
              )}
            </Card.Body>
          </Card>
        </Tab>
      </Tabs>
    </Container>
  );
};

// Helper function to format instructions with line breaks
const formatInstructions = (text) => {
  if (!text) return '';
  if (typeof text === 'object') {
    // If it's an object, try to stringify it or return empty string
    console.error('Instructions should be a string, got object:', text);
    return '';
  }
  // Convert string to HTML with paragraph tags
  return text.split('\n').map((paragraph, i) => 
    `<p class="${i > 0 ? 'mt-3' : ''}">${paragraph}</p>`
  ).join('');
};

// Helper function to get badge color based on difficulty
const getDifficultyBadgeColor = (difficulty) => {
  switch (difficulty) {
    case 'beginner':
      return 'success';
    case 'intermediate':
      return 'warning';
    case 'advanced':
      return 'danger';
    default:
      return 'secondary';
  }
};

export default WebLabView;
