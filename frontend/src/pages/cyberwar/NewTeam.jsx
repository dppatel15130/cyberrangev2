import React, { useState } from 'react';
import { Container, Form, Button, Alert, Card, Row, Col } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import axios from '../../utils/axiosConfig';
import { useAuth } from '../../context/AuthContext';

const NewTeam = () => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    isPublic: true,
    maxMembers: 4,
  });
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { user } = useAuth();

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
    
    try {
      const response = await axios.post('/teams', {
        ...formData,
        maxMembers: parseInt(formData.maxMembers, 10)
      });
      
      // Redirect to the new team's page
      navigate(`/cyberwar/teams/${response.data.id}`);
    } catch (err) {
      console.error('Error creating team:', err);
      setError(err.response?.data?.error || 'Failed to create team. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container className="py-4">
      <Row className="justify-content-center">
        <Col md={8} lg={6}>
          <Card className="shadow-sm">
            <Card.Header className="bg-primary text-white">
              <h4 className="mb-0">Create New Team</h4>
            </Card.Header>
            <Card.Body>
              {error && <Alert variant="danger">{error}</Alert>}
              
              <Form onSubmit={handleSubmit}>
                <Form.Group className="mb-3" controlId="teamName">
                  <Form.Label>Team Name *</Form.Label>
                  <Form.Control
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleChange}
                    placeholder="Enter team name"
                    required
                    maxLength={50}
                  />
                  <Form.Text className="text-muted">
                    Choose a unique name for your team (max 50 characters)
                  </Form.Text>
                </Form.Group>

                <Form.Group className="mb-3" controlId="teamDescription">
                  <Form.Label>Description</Form.Label>
                  <Form.Control
                    as="textarea"
                    name="description"
                    value={formData.description}
                    onChange={handleChange}
                    rows={3}
                    placeholder="Tell others about your team..."
                    maxLength={500}
                  />
                </Form.Group>

                <Row>
                  <Col md={6}>
                    <Form.Group className="mb-3" controlId="teamMaxMembers">
                      <Form.Label>Maximum Team Members</Form.Label>
                      <Form.Select
                        name="maxMembers"
                        value={formData.maxMembers}
                        onChange={handleChange}
                      >
                        {[2, 3, 4, 5, 6, 7, 8, 9, 10].map(num => (
                          <option key={num} value={num}>
                            {num} {num === 1 ? 'member' : 'members'}
                          </option>
                        ))}
                      </Form.Select>
                    </Form.Group>
                  </Col>
                  <Col md={6}>
                    <Form.Group className="mb-3" controlId="teamVisibility">
                      <Form.Label>Team Visibility</Form.Label>
                      <div className="d-flex align-items-center">
                        <Form.Check
                          type="switch"
                          id="team-visibility-switch"
                          name="isPublic"
                          checked={formData.isPublic}
                          onChange={handleChange}
                          label={formData.isPublic ? 'Public (anyone can join)' : 'Private (invite only)'}
                        />
                      </div>
                    </Form.Group>
                  </Col>
                </Row>

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
                    disabled={loading || !formData.name.trim()}
                  >
                    {loading ? 'Creating...' : 'Create Team'}
                  </Button>
                </div>
              </Form>
            </Card.Body>
          </Card>
          
          <div className="mt-4 text-center">
            <p className="text-muted">
              By creating a team, you agree to our{' '}
              <a href="/code-of-conduct" target="_blank" rel="noopener noreferrer">
                Code of Conduct
              </a>
              {' '}and{' '}
              <a href="/terms" target="_blank" rel="noopener noreferrer">
                Terms of Service
              </a>.
            </p>
          </div>
        </Col>
      </Row>
    </Container>
  );
};

export default NewTeam;
