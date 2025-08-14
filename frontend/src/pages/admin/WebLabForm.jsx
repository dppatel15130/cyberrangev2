import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Form, Button, Container, Row, Col, Card, Alert, Spinner, Tabs, Tab } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faFlask, faSave, faArrowLeft } from '@fortawesome/free-solid-svg-icons';
import { Link } from 'react-router-dom';
import axios from '../../utils/axiosConfig';

const WebLabForm = ({ editMode = false, isEdit = false }) => {
  const { labId, id } = useParams();
  const actualId = labId || id;
  const actualEditMode = editMode || isEdit;
  const navigate = useNavigate();
  
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    category: '',
    difficulty: 'intermediate',
    instructions: '',
    htmlContent: '',
    hostedUrl: '',
    validationType: 'header_check',
    validationValue: 'Lab-Status: Completed',
    allowedOrigins: '*',
    points: 100,
    isActive: true
  });
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [activeTab, setActiveTab] = useState('content');
  
  // Load lab data if in edit mode
  useEffect(() => {
    if (actualEditMode && actualId) {
      const fetchLab = async () => {
        try {
          setLoading(true);
          const res = await axios.get(`/weblabs/${actualId}`);
          const { webLabData, webLab, ...labData } = res.data;
          const webLabInfo = webLabData || webLab;
          
          setFormData({
            ...labData,
            ...webLabInfo,
            allowedOrigins: Array.isArray(webLabInfo?.allowedOrigins) 
              ? webLabInfo.allowedOrigins.join(',') 
              : (webLabInfo?.allowedOrigins || '*')
          });
        } catch (err) {
          console.error('Error fetching web lab:', err);
          setError('Failed to load web lab data');
        } finally {
          setLoading(false);
        }
      };
      
      fetchLab();
    }
  }, [actualId, actualEditMode]);
  
  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    
    try {
      const data = {
        ...formData,
        points: parseInt(formData.points) || 100,
        allowedOrigins: formData.allowedOrigins
          .split(',')
          .map(origin => origin.trim())
          .filter(origin => origin.length > 0)
      };
      
      if (actualEditMode) {
        await axios.put(`/weblabs/${actualId}`, data);
        setSuccess('Web lab updated successfully!');
        // Redirect back to labs after successful update
        setTimeout(() => navigate('/admin/labs'), 2000);
      } else {
        await axios.post('/weblabs', data);
        setSuccess('Web lab created successfully!');
        // Reset form after successful creation
        setFormData({
          name: '',
          description: '',
          category: '',
          difficulty: 'intermediate',
          instructions: '',
          htmlContent: '',
          hostedUrl: '',
          validationType: 'header_check',
          validationValue: 'Lab-Status: Completed',
          allowedOrigins: '*',
          points: 100,
          isActive: true
        });
      }
    } catch (err) {
      console.error('Error saving web lab:', {
        message: err.message,
        response: err.response?.data,
        request: err.request,
        config: err.config
      });
      
      const errorMessage = err.response?.data?.message || 
                         err.response?.data?.error || 
                         'Failed to save web lab. Please check the console for more details.';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };
  
  const handleTabSelect = (tab) => {
    setActiveTab(tab);
  };
  
  if (loading && !formData.name) {
    return (
      <Container className="mt-5 text-center">
        <Spinner animation="border" role="status">
          <span className="visually-hidden">Loading...</span>
        </Spinner>
        <p className="mt-2">Loading web lab data...</p>
      </Container>
    );
  }
  
  return (
    <Container className="py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="m-0">
          <FontAwesomeIcon icon={faFlask} className="me-2" />
          {actualEditMode ? 'Edit Web Lab' : 'Create New Web Lab'}
        </h2>
        <Button as={Link} to="/admin/labs" variant="outline-secondary">
          <FontAwesomeIcon icon={faArrowLeft} className="me-2" />
          Back to Labs
        </Button>
      </div>
      
      {error && <Alert variant="danger">{error}</Alert>}
      {success && <Alert variant="success">{success}</Alert>}
      
      <Card className="shadow-sm">
        <Card.Body>
          <Form onSubmit={handleSubmit}>
            <Tabs
              activeKey={activeTab}
              onSelect={handleTabSelect}
              className="mb-3"
            >
              <Tab eventKey="content" title="Content">
                <Card className="mt-3">
                  <Card.Body>
                <Row>
                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Lab Name *</Form.Label>
                      <Form.Control
                        type="text"
                        name="name"
                        value={formData.name}
                        onChange={handleChange}
                        required
                      />
                    </Form.Group>
                  </Col>
                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Category *</Form.Label>
                      <Form.Control
                        type="text"
                        name="category"
                        value={formData.category}
                        onChange={handleChange}
                        required
                      />
                    </Form.Group>
                  </Col>
                </Row>
                
                <Row>
                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Difficulty *</Form.Label>
                      <Form.Select
                        name="difficulty"
                        value={formData.difficulty}
                        onChange={handleChange}
                        required
                      >
                        <option value="beginner">Beginner</option>
                        <option value="intermediate">Intermediate</option>
                        <option value="advanced">Advanced</option>
                      </Form.Select>
                    </Form.Group>
                  </Col>
                  <Col md={6}>
                    <Form.Group className="mb-3">
                      <Form.Label>Points *</Form.Label>
                      <Form.Control
                        type="number"
                        name="points"
                        min="1"
                        value={formData.points}
                        onChange={handleChange}
                        required
                      />
                    </Form.Group>
                  </Col>
                </Row>
                
                <Form.Group className="mb-3">
                  <Form.Label>Description *</Form.Label>
                  <Form.Control
                    as="textarea"
                    rows={3}
                    name="description"
                    value={formData.description}
                    onChange={handleChange}
                    required
                  />
                </Form.Group>
                
                <Form.Group className="mb-3">
                  <Form.Label>Instructions *</Form.Label>
                  <Form.Control
                    as="textarea"
                    rows={5}
                    name="instructions"
                    value={formData.instructions}
                    onChange={handleChange}
                    required
                  />
                </Form.Group>
                
                <Form.Group className="mb-3 form-check">
                  <Form.Check
                    type="checkbox"
                    id="isActive"
                    name="isActive"
                    label="Active"
                    checked={formData.isActive}
                    onChange={handleChange}
                  />
                </Form.Group>
              </Card.Body>
            </Card>
          </Tab>
          
          <Tab eventKey="validation" title="Validation">
            <Card className="mt-3">
              <Card.Body>
                <Form.Group className="mb-3">
                  <Form.Label>Validation Type *</Form.Label>
                  <Form.Select
                    name="validationType"
                    value={formData.validationType}
                    onChange={handleChange}
                    required
                  >
                    <option value="header_check">HTTP Header Check</option>
                    <option value="input_flag">Input Flag</option>
                    <option value="callback">Callback API</option>
                  </Form.Select>
                </Form.Group>
                
                <Form.Group className="mb-3">
                  <Form.Label>
                    {formData.validationType === 'header_check' 
                      ? 'Header and Expected Value *' 
                      : formData.validationType === 'input_flag'
                        ? 'Expected Flag Value *'
                        : 'Callback Validation Value *'}
                  </Form.Label>
                  <Form.Control
                    type="text"
                    name="validationValue"
                    value={formData.validationValue}
                    onChange={handleChange}
                    placeholder={formData.validationType === 'header_check' 
                      ? 'Header-Name: ExpectedValue' 
                      : formData.validationType === 'input_flag'
                        ? 'flag{example_flag}'
                        : 'Any unique identifier for this lab'}
                    required
                  />
                  <Form.Text className="text-muted">
                    {formData.validationType === 'header_check' 
                      ? 'Enter the header name and expected value in the format: Header-Name: ExpectedValue' 
                      : formData.validationType === 'input_flag'
                        ? 'Enter the expected flag value that users need to submit'
                        : 'Enter a unique identifier for this lab that will be used in the callback URL'}
                  </Form.Text>
                </Form.Group>
                
                <Form.Group className="mb-3">
                  <Form.Label>Allowed Origins</Form.Label>
                  <Form.Control
                    type="text"
                    name="allowedOrigins"
                    value={formData.allowedOrigins}
                    onChange={handleChange}
                    placeholder="example.com,sub.example.com"
                  />
                  <Form.Text className="text-muted">
                    Comma-separated list of allowed domains that can embed this lab (leave empty or use * for any)
                  </Form.Text>
                </Form.Group>
              </Card.Body>
            </Card>
          </Tab>
          
          <Tab eventKey="html" title="Lab Content">
            <Card className="mt-3">
              <Card.Body>
                <Form.Group className="mb-3">
                  <Form.Label>External Lab URL</Form.Label>
                  <Form.Control
                    type="url"
                    name="hostedUrl"
                    value={formData.hostedUrl}
                    onChange={handleChange}
                    placeholder="http://labs.example.com/weblab-{{LAB_ID}}"
                  />
                  <Form.Text className="text-muted">
                    Enter the URL where the external lab is hosted. You can use {'{{LAB_ID}}'} as a placeholder for the lab ID.
                    Leave empty if you want to use inline HTML content instead.
                  </Form.Text>
                </Form.Group>

                <hr className="my-4" />
                <p className="text-muted">OR</p>

                <Form.Group className="mb-3">
                  <Form.Label>HTML/JavaScript Content</Form.Label>
                  <Form.Control
                    as="textarea"
                    rows={15}
                    name="htmlContent"
                    value={formData.htmlContent}
                    onChange={handleChange}
                    className="font-monospace"
                    style={{ fontSize: '0.9rem' }}
                  />
                  <Form.Text className="text-muted">
                    Enter the HTML/JavaScript code for the lab. You can use {'{{LAB_ID}}'} as a placeholder for the lab ID.
                    Leave empty if you want to use an external lab URL instead.
                  </Form.Text>
                </Form.Group>
                
                <div className="mt-3">
                  <h5>Preview</h5>
                  <div 
                    className="border p-3" 
                    style={{ 
                      minHeight: '200px',
                      backgroundColor: '#f8f9fa',
                      borderRadius: '0.25rem'
                    }}
                    dangerouslySetInnerHTML={{ 
                      __html: formData.htmlContent 
                        ? formData.htmlContent.replace(/\{\{LAB_ID\}\}/g, 'preview')
                        : '<div class="text-muted">Preview will appear here</div>' 
                    }}
                  />
                </div>
              </Card.Body>
            </Card>
          </Tab>
        </Tabs>
        
        <div className="d-flex justify-content-between mt-4">
          <Button 
            variant="outline-secondary" 
            onClick={() => navigate(-1)}
            disabled={loading}
          >
            Cancel
          </Button>
          
          <Button 
            variant="primary" 
            type="submit" 
            disabled={loading}
          >
            {loading ? (
              <>
                <Spinner
                  as="span"
                  animation="border"
                  size="sm"
                  role="status"
                  aria-hidden="true"
                  className="me-2"
                />
                Saving...
              </>
            ) : (
              <>
                <FontAwesomeIcon icon={faSave} className="me-2" />
                {actualEditMode ? 'Update Web Lab' : 'Create Web Lab'}
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

export default WebLabForm;
