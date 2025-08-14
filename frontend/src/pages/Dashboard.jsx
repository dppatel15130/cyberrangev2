import { useState, useEffect, useContext } from 'react';
import { Link } from 'react-router-dom';
import { Container, Row, Col, Card, Button, Badge, Alert, Spinner } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faFlask, faInfoCircle, faExclamationTriangle, faTrophy } from '@fortawesome/free-solid-svg-icons';
import axios from '../utils/axiosConfig';
import { AuthContext } from '../context/AuthContext';

const Dashboard = () => {
  const [labs, setLabs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [userPoints, setUserPoints] = useState(0);
  const { user } = useContext(AuthContext);

  useEffect(() => {
    const fetchLabs = async () => {
      try {
        const [labsRes, userStatsRes] = await Promise.all([
          axios.get('/labs'),
          axios.get('/flags/user-stats')
        ]);
        console.log('Labs response:', labsRes.data);
        const labsData = Array.isArray(labsRes.data) ? labsRes.data : [];
        setLabs(labsData);
        
        setUserPoints(userStatsRes.data.user.totalPoints || 0);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching labs:', err);
        setError('Failed to load labs. Please try again later.');
        setLoading(false);
      }
    };

    fetchLabs();
  }, []);

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



  if (loading) {
    return (
      <Container className="py-5 text-center">
        <Spinner animation="border" variant="primary" />
        <p className="mt-3">Loading labs...</p>
      </Container>
    );
  }

  return (
    <Container className="py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1 className="mb-0">
          <FontAwesomeIcon icon={faFlask} className="me-2" />
          My Labs
        </h1>
        <Badge bg="primary" className="fs-6 px-3 py-2">
          <FontAwesomeIcon icon={faTrophy} className="me-1" />
          {userPoints.toLocaleString()} Points
        </Badge>
      </div>


      {error && (
        <Alert variant="danger">
          <FontAwesomeIcon icon={faExclamationTriangle} className="me-2" />
          {error}
        </Alert>
      )}

      {labs.length === 0 ? (
        <Alert variant="info">
          <FontAwesomeIcon icon={faInfoCircle} className="me-2" />
          No labs have been assigned to you yet. Please contact an administrator.
        </Alert>
      ) : (
        <Row xs={1} md={2} lg={3} className="g-4">
          {labs.map((lab) => (
            <Col key={lab.id || lab._id}>
              <Card className="h-100 shadow-sm">
                <Card.Body>
                  <Card.Title>{lab.name}</Card.Title>
                  <div className="mb-2">
                    {getDifficultyBadge(lab.difficulty)}
                    {lab.category && <Badge bg="info" className="ms-2">{lab.category}</Badge>}
                  </div>
                  <Card.Text>
                    {lab.description.length > 100
                      ? `${lab.description.substring(0, 100)}...`
                      : lab.description}
                  </Card.Text>
                </Card.Body>
                <Card.Footer className="bg-white border-top-0">
                  <Button
                    as={Link}
                    to={`/labs/${lab.id || lab._id}`}
                    variant="primary"
                    className="w-100"
                  >
                    View Details
                  </Button>
                </Card.Footer>
              </Card>
            </Col>
          ))}
        </Row>
      )}
    </Container>
  );
};

export default Dashboard;