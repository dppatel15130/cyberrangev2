import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Button, Spinner, Alert } from 'react-bootstrap';
import { Link, useNavigate } from 'react-router-dom';
import axios from '../../utils/axiosConfig';

const Teams = () => {
  const [teams, setTeams] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 10,
    total: 0,
    pages: 1
  });
  const navigate = useNavigate();

  const fetchTeams = async (page = 1, limit = 10) => {
    try {
      setLoading(true);
      const response = await axios.get('/teams', {
        params: { page, limit }
      });
      setTeams(response.data.teams);
      setPagination({
        page: response.data.pagination.currentPage,
        limit: response.data.pagination.limit,
        total: response.data.pagination.total,
        pages: response.data.pagination.pages
      });
      setError(null);
    } catch (err) {
      console.error('Error fetching teams:', err);
      setError('Failed to load teams. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTeams();
  }, []);

  const handlePageChange = (newPage) => {
    fetchTeams(newPage, pagination.limit);
  };

  if (loading && teams.length === 0) {
    return (
      <Container className="text-center py-5">
        <Spinner animation="border" role="status">
          <span className="visually-hidden">Loading...</span>
        </Spinner>
        <p className="mt-2">Loading teams...</p>
      </Container>
    );
  }

  if (error) {
    return (
      <Container className="py-4">
        <Alert variant="danger">
          <Alert.Heading>Error Loading Teams</Alert.Heading>
          <p>{error}</p>
          <Button variant="outline-danger" onClick={() => fetchTeams()}>
            Retry
          </Button>
        </Alert>
      </Container>
    );
  }

  return (
    <Container className="py-4">
      <Row className="mb-4">
        <Col>
          <h2>My Teams</h2>
          <p className="text-muted">Manage your cyber warfare teams and join matches</p>
        </Col>
        <Col className="text-end">
          <Button as={Link} to="/cyberwar/teams/new" variant="primary">
            Create New Team
          </Button>
        </Col>
      </Row>

      {teams.length === 0 ? (
        <div className="text-center py-5">
          <h4>No teams found</h4>
          <p className="text-muted">Be the first to create a team!</p>
          <Button variant="primary" onClick={() => navigate('/cyberwar/teams/new')}>
            Create Team
          </Button>
        </div>
      ) : (
        <>
          <Row xs={1} md={2} lg={3} className="g-4">
            {teams.map((team) => (
              <Col key={team.id}>
                <Card className="h-100">
                  <Card.Body>
                    <Card.Title>{team.name}</Card.Title>
                    <Card.Text>
                      Members: {team.memberCount || team.members?.length || 0}<br />
                      {team.score && `Score: ${team.score}`}
                      {team.matches && team.matches.length > 0 && (
                        <>
                          <br />
                          Active Matches: {team.matches.filter(m => m.status === 'active').length}
                        </>
                      )}
                    </Card.Text>
                    <div className="d-flex">
                      <Button 
                        as={Link} 
                        to={`/cyberwar/teams/${team.id}`} 
                        variant="outline-primary"
                        className="me-2"
                        size="sm"
                      >
                        View Team
                      </Button>
                      <Button 
                        variant="outline-secondary" 
                        size="sm"
                        onClick={() => navigate('/cyberwar/lobby')}
                      >
                        Join Match
                      </Button>
                    </div>
                  </Card.Body>
                </Card>
              </Col>
            ))}
          </Row>
          
          {pagination.pages > 1 && (
            <div className="d-flex justify-content-center mt-4">
              <nav>
                <ul className="pagination">
                  <li className={`page-item ${pagination.page === 1 ? 'disabled' : ''}`}>
                    <button 
                      className="page-link" 
                      onClick={() => handlePageChange(pagination.page - 1)}
                      disabled={pagination.page === 1}
                    >
                      Previous
                    </button>
                  </li>
                  {Array.from({ length: Math.min(5, pagination.pages) }, (_, i) => {
                    let pageNum;
                    if (pagination.pages <= 5) {
                      pageNum = i + 1;
                    } else if (pagination.page <= 3) {
                      pageNum = i + 1;
                    } else if (pagination.page >= pagination.pages - 2) {
                      pageNum = pagination.pages - 4 + i;
                    } else {
                      pageNum = pagination.page - 2 + i;
                    }
                    
                    return (
                      <li key={pageNum} className={`page-item ${pagination.page === pageNum ? 'active' : ''}`}>
                        <button className="page-link" onClick={() => handlePageChange(pageNum)}>
                          {pageNum}
                        </button>
                      </li>
                    );
                  })}
                  <li className={`page-item ${pagination.page === pagination.pages ? 'disabled' : ''}`}>
                    <button 
                      className="page-link" 
                      onClick={() => handlePageChange(pagination.page + 1)}
                      disabled={pagination.page === pagination.pages}
                    >
                      Next
                    </button>
                  </li>
                </ul>
              </nav>
            </div>
          )}
        </>
      )}
    </Container>
  );
};

export default Teams;
