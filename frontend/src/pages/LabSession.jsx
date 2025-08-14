import { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { Container, Row, Col, Card, Button, Alert, Spinner, Form, Modal } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faStop, faArrowLeft, faExclamationTriangle, faCheckCircle, faFlag } from '@fortawesome/free-solid-svg-icons';
import axios from '../utils/axiosConfig';

const LabSession = () => {
  const { labId, vmId } = useParams();
  const navigate = useNavigate();
  
  const [lab, setLab] = useState(null);
  const [vmInfo, setVmInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stoppingLab, setStoppingLab] = useState(false);
  const [showFlagModal, setShowFlagModal] = useState(false);
  const [flagInput, setFlagInput] = useState('');
  const [flagResult, setFlagResult] = useState(null);
  const [submittingFlag, setSubmittingFlag] = useState(false);

  useEffect(() => {
    const fetchLabAndVmInfo = async () => {
      try {
        // Fetch lab details
        const labRes = await axios.get(`/labs/${labId}`);
        setLab(labRes.data);
        
        // Fetch VM status
        const vmRes = await axios.get(`/vms/status/${vmId}`);
        setVmInfo(vmRes.data);
        
        setLoading(false);
      } catch (err) {
        console.error('Error fetching lab session data:', err);
        setError('Failed to load lab session. Please try again later.');
        setLoading(false);
      }
    };

    fetchLabAndVmInfo();
    
    // Poll VM status every 30 seconds
    const intervalId = setInterval(async () => {
      try {
        const vmRes = await axios.get(`/vms/status/${vmId}`);
        setVmInfo(vmRes.data);
      } catch (err) {
        console.error('Error polling VM status:', err);
      }
    }, 30000);
    
    return () => clearInterval(intervalId);
  }, [labId, vmId]);

  const stopLab = async () => {
    try {
      setStoppingLab(true);
      setError(null);
      
      await axios.post('/vms/stop', { vmId });
      
      // Redirect to lab details page
      navigate(`/labs/${labId}`);
    } catch (err) {
      console.error('Error stopping lab:', err);
      setError('Failed to stop lab. Please try again later.');
      setStoppingLab(false);
    }
  };

  const handleFlagSubmit = async (e) => {
    e.preventDefault();
    setSubmittingFlag(true);
    setFlagResult(null);
    
    try {
      // In a real app, you would verify the flag with the backend
      // This is a simplified example
      if (lab && flagInput === lab.flag) {
        setFlagResult({
          success: true,
          message: 'Congratulations! You captured the flag!'
        });
      } else {
        setFlagResult({
          success: false,
          message: 'Incorrect flag. Try again!'
        });
      }
    } catch (err) {
      console.error('Error submitting flag:', err);
      setFlagResult({
        success: false,
        message: 'Error submitting flag. Please try again.'
      });
    } finally {
      setSubmittingFlag(false);
    }
  };

  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" />
        <p className="mt-3">Loading lab session...</p>
      </Container>
    );
  }

  if (!lab || !vmInfo) {
    return (
      <Container className="py-5">
        <Alert variant="danger">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          Lab session not found or has expired.
        </Alert>
        <Button as={Link} to="/dashboard" variant="secondary">
          <FontAwesomeIcon icon={faArrowLeft} className="me-2" />
          Back to Dashboard
        </Button>
      </Container>
    );
  }

  return (
    <Container fluid className="py-3">
      <Row className="mb-3">
        <Col>
          <div className="d-flex justify-content-between align-items-center">
            <h2 className="mb-0">{lab.name} - Active Session</h2>
            <div>
              <Button 
                variant="outline-primary" 
                className="me-2"
                onClick={() => setShowFlagModal(true)}
              >
                <FontAwesomeIcon icon={faFlag} className="me-2" />
                Submit Flag
              </Button>
              <Button 
                variant="danger" 
                onClick={stopLab}
                disabled={stoppingLab}
              >
                {stoppingLab ? (
                  <>
                    <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
                    Stopping...
                  </>
                ) : (
                  <>
                    <FontAwesomeIcon icon={faStop} className="me-2" />
                    Stop Lab
                  </>
                )}
              </Button>
            </div>
          </div>
        </Col>
      </Row>

      {error && (
        <Alert variant="danger" className="mb-3">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      <Row>
        <Col>
          <Card className="shadow-sm mb-4">
            <Card.Body>
              <div className="ratio ratio-16x9">
                {/* In a real application, this would be replaced with a Guacamole client iframe */}
                <div className="bg-dark d-flex align-items-center justify-content-center text-white">
                  <div className="text-center">
                    <h4>VM Console</h4>
                    <p>In a production environment, this would display the Guacamole remote desktop connection.</p>
                    <p>VM ID: {vmId}</p>
                    <p>Status: {vmInfo.status}</p>
                    <p>IP Address: {vmInfo.ipAddress || 'Not available'}</p>
                  </div>
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Flag Submission Modal */}
      <Modal show={showFlagModal} onHide={() => setShowFlagModal(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Submit Flag</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form onSubmit={handleFlagSubmit}>
            <Form.Group className="mb-3">
              <Form.Label>Enter the flag you found:</Form.Label>
              <Form.Control
                type="text"
                placeholder="Enter your flag within flag {...}"
                value={flagInput}
                onChange={(e) => setFlagInput(e.target.value)}
                required
              />
            </Form.Group>

            {flagResult && (
              <Alert variant={flagResult.success ? 'success' : 'danger'}>
                <FontAwesomeIcon 
                  icon={flagResult.success ? faCheckCircle : faExclamationTriangle} 
                  className="me-2" 
                />
                {flagResult.message}
              </Alert>
            )}

            <div className="d-grid gap-2">
              <Button 
                variant="primary" 
                type="submit"
                disabled={submittingFlag}
              >
                {submittingFlag ? (
                  <>
                    <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
                    Verifying...
                  </>
                ) : 'Submit Flag'}
              </Button>
            </div>
          </Form>
        </Modal.Body>
      </Modal>
    </Container>
  );
};

export default LabSession;