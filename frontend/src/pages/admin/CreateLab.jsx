import { useState } from 'react';
import {Container, Row, Col, Card, Form, Button, Alert, Spinner, InputGroup} from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faArrowLeft,
  faBook,
  faCheck,
  faClock,
  faDesktop,
  faExclamationTriangle,
  faFlag,
  faFlask,
  faInfoCircle,
  faLayerGroup,
  faSave,
  faTimes,
  faTachometerAlt,
  faUserTie,
  faCalendarAlt,
  faAlignLeft,
  faClipboardQuestion,
  faLock,
  faGear
} from '@fortawesome/free-solid-svg-icons';
import { Link, useNavigate } from 'react-router-dom';
import axios from '../../utils/axiosConfig';


const CreateLab = () => {
  const navigate = useNavigate();
  
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    category: 'Web Security', // Default category
    difficulty: 'beginner',   // Default difficulty
    instructions: '',
    flag: 'flag{',
    vmTemplateId: '100',      // Default template ID
    duration: '60',           // Default duration in minutes
    points: '100',            // Default points for completing the lab
    isActive: true           // Default active status
  });
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      // Ensure flag is properly formatted
      const formattedFormData = {
        ...formData,
        flag: formData.flag.startsWith('flag{') ? formData.flag : `flag{${formData.flag}}`,
        duration: parseInt(formData.duration) || 60
      };
      
      const res = await axios.post('/labs', formattedFormData);
      navigate('/admin/labs', { state: { success: 'Lab created successfully!' } });
    } catch (err) {
      console.error('Error creating lab:', err);
      setError(err.response?.data?.message || 'Failed to create lab. Please check your input and try again.');
      setLoading(false);
    }
  };
  


  return (
    <Container className="py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <Button as={Link} to="/admin/labs" variant="outline-secondary" size="sm" className="mb-2">
            <FontAwesomeIcon icon={faArrowLeft} className="me-2" />
            Back to Labs
          </Button>
          <h1 className="mb-0">
            <FontAwesomeIcon icon={faFlask} className="me-2" />
            Create New Lab
          </h1>
        </div>
      </div>

      {error && (
        <Alert variant="danger" className="mb-4">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      <Card className="shadow-sm mb-4">
        <Card.Body>
          <Form onSubmit={handleSubmit}>
            <h5 className="mb-4 border-bottom pb-2">
              <FontAwesomeIcon icon={faDesktop} className="me-2 text-primary" />
              Lab Information
            </h5>
            
            <Row className="mb-4">
              <Col md={8}>
                <Form.Group className="mb-3">
                  <Form.Label className="fw-bold">
                    <FontAwesomeIcon icon={faFlask} className="me-2 text-primary" />
                    Lab Name
                  </Form.Label>
                  <Form.Control
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleInputChange}
                    required
                    placeholder="Enter a descriptive lab name"
                    className="form-control-lg"
                  />
                </Form.Group>
              </Col>
              <Col md={4}>
                <Form.Group className="mb-3">
                  <Form.Label className="fw-bold">
                    <FontAwesomeIcon icon={faTachometerAlt} className="me-2 text-primary" />
                    Difficulty
                  </Form.Label>
                  <Form.Select
                    name="difficulty"
                    value={formData.difficulty}
                    onChange={handleInputChange}
                    required
                    className="form-select-lg"
                  >
                    <option value="beginner">Beginner</option>
                    <option value="intermediate">Intermediate</option>
                    <option value="advanced">Advanced</option>
                  </Form.Select>
                </Form.Group>
              </Col>
            </Row>

            <Row className="mb-4">
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label className="fw-bold">
                    <FontAwesomeIcon icon={faLayerGroup} className="me-2 text-primary" />
                    Category
                  </Form.Label>
                  <Form.Control
                    type="text"
                    name="category"
                    value={formData.category}
                    onChange={handleInputChange}
                    required
                    placeholder="e.g., Web Security, Network, Forensics"
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label className="fw-bold">
                    <FontAwesomeIcon icon={faDesktop} className="me-2 text-primary" />
                    VM Template ID
                  </Form.Label>
                  <Form.Control
                    type="text"
                    name="vmTemplateId"
                    value={formData.vmTemplateId}
                    onChange={handleInputChange}
                    required
                    placeholder="Enter Proxmox VM template ID"
                  />
                  <Form.Text className="text-muted">
                    <FontAwesomeIcon icon={faInfoCircle} className="me-1" />
                    The VM template ID from Proxmox that will be used for this lab.
                  </Form.Text>
                </Form.Group>
              </Col>
            </Row>

            <Form.Group className="mb-4">
              <Form.Label className="fw-bold">
                <FontAwesomeIcon icon={faAlignLeft} className="me-2 text-primary" />
                Description
              </Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                required
                placeholder="Provide a brief overview of what this lab is about"
              />
            </Form.Group>

            <h5 className="mb-3 border-bottom pt-3 pb-2">
              <FontAwesomeIcon icon={faInfoCircle} className="me-2 text-primary" />
              Lab Content
            </h5>

            <Form.Group className="mb-4">
              <Form.Label className="fw-bold">
                <FontAwesomeIcon icon={faClipboardQuestion} className="me-2 text-primary" />
                Instructions
              </Form.Label>
              <Form.Control
                as="textarea"
                rows={6}
                name="instructions"
                value={formData.instructions}
                onChange={handleInputChange}
                required
                placeholder="Provide step-by-step instructions for the lab"
              />
              <Form.Text className="text-muted">
                <FontAwesomeIcon icon={faInfoCircle} className="me-1" />
                You can use basic formatting like line breaks. HTML is not supported.
              </Form.Text>
            </Form.Group>

            <Form.Group className="mb-4">
              <Form.Label className="fw-bold">
                <FontAwesomeIcon icon={faFlag} className="me-2 text-primary" />
                Flag
              </Form.Label>
              <InputGroup>
                <InputGroup.Text>
                  <FontAwesomeIcon icon={faLock} />
                </InputGroup.Text>
                <Form.Control
                  type="text"
                  name="flag"
                  value={formData.flag}
                  onChange={handleInputChange}
                  required
                  placeholder="s0m3_fl4g_h3r3"
                />
              </InputGroup>
              <Form.Text className="text-muted">
                <FontAwesomeIcon icon={faInfoCircle} className="me-1" />
                This is the flag that users need to find to complete the lab. It will be automatically wrapped in 'flag{}' if not already.
              </Form.Text>
            </Form.Group>

            <h5 className="mb-3 border-top pt-3 pb-2">
              <FontAwesomeIcon icon={faGear} className="me-2 text-primary" />
              Additional Settings
            </h5>

            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label className="fw-bold">
                    <FontAwesomeIcon icon={faClock} className="me-2 text-primary" />
                    Duration (minutes)
                  </Form.Label>
                  <Form.Control
                    type="number"
                    name="duration"
                    value={formData.duration}
                    onChange={handleInputChange}
                    min="1"
                    placeholder="Estimated time to complete in minutes"
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label className="fw-bold">
                    <FontAwesomeIcon icon={faFlag} className="me-2 text-primary" />
                    Points
                  </Form.Label>
                  <Form.Control
                    type="number"
                    name="points"
                    value={formData.points}
                    onChange={handleInputChange}
                    min="1"
                    required
                    placeholder="Points awarded for completing this lab"
                  />
                  <Form.Text className="text-muted">
                    <FontAwesomeIcon icon={faInfoCircle} className="me-1" />
                    Points will be awarded when users successfully submit the correct flag.
                  </Form.Text>
                </Form.Group>
              </Col>
            </Row>

            <div className="d-flex justify-content-between mt-4 pt-3 border-top">
              <Button 
                variant="outline-secondary" 
                as={Link} 
                to="/admin/labs"
                disabled={loading}
              >
                <FontAwesomeIcon icon={faTimes} className="me-2" />
                Cancel
              </Button>
              <div className="d-flex gap-2">
                <Button 
                  variant="outline-primary"
                  type="button"
                  onClick={() => {
                    // Save as draft functionality
                    console.log('Save as draft');
                  }}
                  disabled={loading}
                >
                  <FontAwesomeIcon icon={faSave} className="me-2" />
                  Save Draft
                </Button>
                <Button 
                  variant="primary" 
                  type="submit" 
                  disabled={loading}
                  className="px-4"
                >
                  {loading ? (
                    <>
                      <Spinner as="span" animation="border" size="sm" className="me-2" />
                      Creating...
                    </>
                  ) : (
                    <>
                      <FontAwesomeIcon icon={faCheck} className="me-2" />
                      Create Lab
                    </>
                  )}
                </Button>
              </div>
            </div>
          </Form>
        </Card.Body>
      </Card>
    </Container>
  );
};

export default CreateLab;