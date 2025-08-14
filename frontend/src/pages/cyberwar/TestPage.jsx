import { useContext } from 'react';
import { Container, Card, Alert } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCheckCircle } from '@fortawesome/free-solid-svg-icons';
import { AuthContext } from '../../context/AuthContext';

const TestPage = () => {
  const { user, isAdmin } = useContext(AuthContext);

  return (
    <Container className="py-4">
      <Card>
        <Card.Header>
          <FontAwesomeIcon icon={faCheckCircle} className="me-2 text-success" />
          Cyber-Warfare Navigation Test
        </Card.Header>
        <Card.Body>
          <Alert variant="success">
            <strong>Success!</strong> You have successfully navigated to the cyber-warfare section.
          </Alert>
          
          <div className="mt-3">
            <h6>User Information:</h6>
            <ul>
              <li><strong>Username:</strong> {user?.username}</li>
              <li><strong>Role:</strong> {user?.role}</li>
              <li><strong>Is Admin:</strong> {isAdmin() ? 'Yes' : 'No'}</li>
              <li><strong>User Object:</strong> {JSON.stringify(user, null, 2)}</li>
            </ul>
          </div>

          <Alert variant="info">
            This is a test page to verify that cyber-warfare routes are working correctly.
            If you can see this page, the navigation is working properly.
          </Alert>
        </Card.Body>
      </Card>
    </Container>
  );
};

export default TestPage;
