import { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Form, Button, Alert, Spinner } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faFlask, 
  faSave, 
  faArrowLeft, 
  faExclamationTriangle,
  faPlus,
  faTrash,
  faListCheck,
  faClipboardCheck,
  faClock
} from '@fortawesome/free-solid-svg-icons';
import { Link, useParams, useNavigate } from 'react-router-dom';
import axios from '../../utils/axiosConfig';

const EditLab = () => {
  const { labId } = useParams();
  const navigate = useNavigate();
  
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    category: 'Web Security',
    difficulty: 'beginner',
    instructions: '',
    flag: 'flag{',
    vmTemplateId: '100',
    active: true,
    duration: '60',
    points: '100'
  });
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchLabDetails = async () => {
      try {
        const res = await axios.get(`/labs/${labId}`);
        
        // Set form data from lab details
        setFormData({
          name: res.data.name || '',
          description: res.data.description || '',
          category: res.data.category || 'Web Security',
          difficulty: res.data.difficulty || 'beginner',
          instructions: typeof res.data.instructions === 'string' ? res.data.instructions : (res.data.instructions ? JSON.stringify(res.data.instructions) : ''),
          flag: res.data.flag || 'flag{',
          vmTemplateId: res.data.vmTemplateId || '100',
          active: res.data.isActive !== undefined ? res.data.isActive : (res.data.active !== undefined ? res.data.active : true),
          duration: res.data.duration ? String(res.data.duration) : '60',
          points: res.data.points ? String(res.data.points) : '100'
        });
        
        setLoading(false);
      } catch (err) {
        console.error('Error fetching lab details:', err);
        setError('Failed to load lab details. Please try again later.');
        setLoading(false);
      }
    };

    fetchLabDetails();
  }, [labId]);

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };



  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    
    try {
      // Ensure flag is properly formatted
      const formattedFormData = {
        ...formData,
        flag: formData.flag.startsWith('flag{') ? formData.flag : `flag{${formData.flag}}`,
        duration: parseInt(formData.duration) || 60,
        points: parseInt(formData.points) || 100
      };
      
      await axios.put(`/labs/${labId}`, formattedFormData);
      navigate('/admin/labs', { state: { success: 'Lab updated successfully!' } });
    } catch (err) {
      console.error('Error updating lab:', err);
      setError(err.response?.data?.message || 'Failed to update lab. Please try again later.');
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" />
        <p className="mt-3">Loading lab details...</p>
      </Container>
    );
  }

  return (
    <Container className="py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1>
          <FontAwesomeIcon icon={faFlask} className="me-2" />
          Edit Lab
        </h1>
        <Button as={Link} to="/admin/labs" variant="outline-secondary">
          <FontAwesomeIcon icon={faArrowLeft} className="me-2" />
          Back to Labs
        </Button>
      </div>

      {error && (
        <Alert variant="danger" className="mb-4">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      <Card className="shadow-sm">
        <Card.Body>
          <Form onSubmit={handleSubmit}>
            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Lab Name</Form.Label>
                  <Form.Control
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleInputChange}
                    required
                    placeholder="Enter lab name"
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>VM Template ID</Form.Label>
                  <Form.Control
                    type="text"
                    name="vmTemplateId"
                    value={formData.vmTemplateId}
                    onChange={handleInputChange}
                    required
                    placeholder="Enter Proxmox VM template ID"
                  />
                </Form.Group>
              </Col>
            </Row>

            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Category</Form.Label>
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
                  <Form.Label>Difficulty</Form.Label>
                  <Form.Select
                    name="difficulty"
                    value={formData.difficulty}
                    onChange={handleInputChange}
                    required
                  >
                    <option value="">Select Difficulty</option>
                    <option value="beginner">Beginner</option>
                    <option value="intermediate">Intermediate</option>
                    <option value="advanced">Advanced</option>
                  </Form.Select>
                </Form.Group>
              </Col>
            </Row>

            <Form.Group className="mb-3">
              <Form.Label>Description</Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                required
                placeholder="Enter lab description"
              />
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>Instructions</Form.Label>
              <Form.Control
                as="textarea"
                rows={6}
                name="instructions"
                value={formData.instructions}
                onChange={handleInputChange}
                required
                placeholder="Enter detailed lab instructions"
              />
              <Form.Text className="text-muted">
                You can use basic formatting like line breaks. HTML is not supported.
              </Form.Text>
            </Form.Group>



            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>
                    <FontAwesomeIcon icon={faClock} className="me-2" />
                    Duration (minutes)
                  </Form.Label>
                  <Form.Control
                    type="number"
                    name="duration"
                    value={formData.duration}
                    onChange={handleInputChange}
                    min="1"
                    required
                    className="w-auto"
                    style={{ maxWidth: '150px' }}
                  />
                  <Form.Text className="text-muted">
                    Estimated time to complete the lab (in minutes)
                  </Form.Text>
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>
                    <FontAwesomeIcon icon={faListCheck} className="me-2" />
                    Points
                  </Form.Label>
                  <Form.Control
                    type="number"
                    name="points"
                    value={formData.points}
                    onChange={handleInputChange}
                    min="1"
                    required
                    className="w-auto"
                    style={{ maxWidth: '150px' }}
                  />
                  <Form.Text className="text-muted">
                    Points awarded when users submit the correct flag
                  </Form.Text>
                </Form.Group>
              </Col>
            </Row>

            <Form.Group className="mb-3">
              <Form.Label>Flag</Form.Label>
              <Form.Control
                type="text"
                name="flag"
                value={formData.flag}
                onChange={handleInputChange}
                required
                placeholder="e.g., flag{s0m3_fl4g_h3r3}"
              />
              <Form.Text className="text-muted">
                This is the flag that users need to find to complete the lab.
              </Form.Text>
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Check
                type="checkbox"
                label="Active"
                name="active"
                checked={formData.active}
                onChange={handleInputChange}
              />
              <Form.Text className="text-muted">
                Inactive labs will not be available to users.
              </Form.Text>
            </Form.Group>

            <div className="d-grid gap-2">
              <Button variant="primary" type="submit" disabled={saving}>
                {saving ? (
                  <>
                    <Spinner as="span" animation="border" size="sm" role="status" aria-hidden="true" className="me-2" />
                    Saving Changes...
                  </>
                ) : (
                  <>
                    <FontAwesomeIcon icon={faSave} className="me-2" />
                    Save Changes
                  </>
                )}
              </Button>
            </div>
          </Form>
        </Card.Body>
      </Card>
    </Container>
  );
};

export default EditLab;