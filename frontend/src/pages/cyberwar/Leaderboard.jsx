import React, { useState, useEffect } from 'react';
import { Container, Table, Form, Row, Col, Spinner, Alert } from 'react-bootstrap';
import axios from '../../utils/axiosConfig';

const Leaderboard = () => {
  const [leaderboardData, setLeaderboardData] = useState([]);
  const [timeRange, setTimeRange] = useState('all');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRangeOptions] = useState([
    { value: 'all', label: 'All Time' },
    { value: 'month', label: 'This Month' },
    { value: 'week', label: 'This Week' },
    { value: 'day', label: 'Today' }
  ]);

  // Fetch leaderboard data from the API
  const fetchLeaderboard = async (range = 'all') => {
    try {
      setIsLoading(true);
      setError(null);
      
      // Call the API endpoint with the selected time range
      const response = await axios.get('/flags/leaderboard', {
        params: { range }
      });
      
      // Transform the API response to match our component's expected format
      const formattedData = response.data.leaderboard.map((entry, index) => ({
        rank: index + 1,
        team: entry.teamName || entry.username || `Team ${index + 1}`,
        score: entry.totalPoints || 0,
        matches: entry.matchesPlayed || 0,
        wins: entry.wins || 0,
        ...entry // Include all other fields from the API
      }));
      
      setLeaderboardData(formattedData);
    } catch (err) {
      console.error('Error fetching leaderboard:', err);
      setError('Failed to load leaderboard. Please try again later.');
      
      // Fallback to mock data if API fails (for development)
      if (process.env.NODE_ENV === 'development') {
        console.warn('Using mock data due to API error');
        setLeaderboardData([
          { rank: 1, team: 'CyberNinjas', score: 2450, matches: 12, wins: 10 },
          { rank: 2, team: 'HackThePlanet', score: 2300, matches: 15, wins: 11 },
          { rank: 3, team: 'ZeroDay', score: 2150, matches: 10, wins: 8 },
          { rank: 4, team: 'PhishMeIfYouCan', score: 2000, matches: 14, wins: 9 },
          { rank: 5, team: 'FirewallFighters', score: 1950, matches: 11, wins: 7 },
        ]);
        setError(null);
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLeaderboard(timeRange);
  }, [timeRange]);

  if (isLoading && leaderboardData.length === 0) {
    return (
      <Container className="py-4 text-center">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
        <p className="mt-2">Loading leaderboard...</p>
      </Container>
    );
  }

  if (error) {
    return (
      <Container className="py-4">
        <Alert variant="danger">
          <Alert.Heading>Error Loading Leaderboard</Alert.Heading>
          <p>{error}</p>
          <button 
            className="btn btn-outline-danger" 
            onClick={() => fetchLeaderboard(timeRange)}
          >
            Retry
          </button>
        </Alert>
      </Container>
    );
  }

  return (
    <Container className="py-4">
      <Row className="mb-4">
        <Col>
          <h2>Leaderboard</h2>
          <p className="text-muted">Top performing teams in cyber warfare challenges</p>
        </Col>
        <Col md={4}>
          <Form.Group controlId="timeRange">
            <Form.Label>Time Range</Form.Label>
            <Form.Select 
              value={timeRange} 
              onChange={(e) => setTimeRange(e.target.value)}
            >
              {timeRangeOptions.map(option => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Form.Select>
          </Form.Group>
        </Col>
      </Row>

      <Table striped bordered hover responsive>
        <thead>
          <tr>
            <th>Rank</th>
            <th>Team</th>
            <th className="text-end">Score</th>
            <th className="text-center">Matches</th>
            <th className="text-center">Win Rate</th>
          </tr>
        </thead>
        <tbody>
          {leaderboardData.length > 0 ? (
            leaderboardData.map((entry) => (
              <tr key={entry.rank} className={entry.isCurrentUser ? 'table-primary' : ''}>
                <td className="fw-bold">#{entry.rank}</td>
                <td className="fw-bold">
                  {entry.team}
                  {entry.isCurrentUser && (
                    <span className="badge bg-primary ms-2">You</span>
                  )}
                </td>
                <td className="text-end">{entry.score.toLocaleString()}</td>
                <td className="text-center">{entry.matches}</td>
                <td className="text-center">
                  {entry.matches > 0 ? (
                    `${Math.round((entry.wins / entry.matches) * 100)}%`
                  ) : 'N/A'}
                </td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan="5" className="text-center py-4">
                <p className="text-muted">No leaderboard data available</p>
                <button 
                  className="btn btn-outline-primary"
                  onClick={() => fetchLeaderboard(timeRange)}
                >
                  Refresh
                </button>
              </td>
            </tr>
          )}
        </tbody>
      </Table>

      <div className="text-muted text-center mt-4">
        <small>Last updated: {new Date().toLocaleString()}</small>
      </div>
    </Container>
  );
};

export default Leaderboard;
