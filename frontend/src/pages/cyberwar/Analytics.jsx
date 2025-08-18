import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Form, Tab, Tabs, Spinner, Alert } from 'react-bootstrap';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import axios from '../../utils/axiosConfig';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';

// Register ChartJS components and plugins
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const Analytics = () => {
  const [timeRange, setTimeRange] = useState('month');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [analyticsData, setAnalyticsData] = useState({
    performance: { labels: [], datasets: [] },
    categories: { labels: [], datasets: [] },
    teamComparison: { labels: [], datasets: [] },
    metrics: []
  });

  // Fetch analytics data from the backend
  const fetchAnalyticsData = async (range = 'month') => {
    try {
      setIsLoading(true);
      setError(null);

      // Fetch performance data (example: points over time)
      const [performanceRes, categoriesRes, teamRes] = await Promise.all([
        axios.get('/analytics/performance', { params: { range } })
          .catch(() => ({ data: { labels: [], data: [] } })),
        
        axios.get('/analytics/categories', { params: { range } })
          .catch(() => ({ data: { labels: [], data: [] } })),
        
        axios.get('/teams/stats')
          .catch(() => ({ data: { teams: [] } }))
      ]);

      // Process performance data
      const performanceData = {
        labels: performanceRes.data.labels || ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
        datasets: [
          {
            label: 'Your Team',
            data: performanceRes.data.data || [65, 78, 82, 90],
            borderColor: 'rgb(75, 192, 192)',
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            tension: 0.3,
            fill: true
          },
          {
            label: 'Average',
            data: performanceRes.data.average || [50, 60, 70, 80],
            borderColor: 'rgb(201, 203, 207)',
            borderDash: [5, 5],
            backgroundColor: 'transparent',
            tension: 0.3
          }
        ]
      };

      // Process categories data
      const categoriesData = {
        labels: categoriesRes.data.labels || ['Web Exploits', 'Network Security', 'Forensics', 'Cryptography', 'Reverse Engineering'],
        datasets: [
          {
            label: 'Challenges Completed',
            data: categoriesRes.data.data || [12, 19, 3, 5, 2],
            backgroundColor: [
              'rgba(255, 99, 132, 0.7)',
              'rgba(54, 162, 235, 0.7)',
              'rgba(255, 206, 86, 0.7)',
              'rgba(75, 192, 192, 0.7)',
              'rgba(153, 102, 255, 0.7)'
            ],
            borderWidth: 1,
          },
        ],
      };

      // Process team comparison data
      const teams = teamRes.data.teams || [
        { name: 'Your Team', score: 85 },
        { name: 'Top 25%', score: 90 },
        { name: 'Average', score: 65 },
        { name: 'Your Rank', score: 8 }
      ];

      const teamComparisonData = {
        labels: teams.map(t => t.name),
        datasets: [
          {
            label: 'Score',
            data: teams.map(t => t.score),
            backgroundColor: [
              'rgba(75, 192, 192, 0.7)',
              'rgba(54, 162, 235, 0.7)',
              'rgba(255, 206, 86, 0.7)',
              'rgba(153, 102, 255, 0.7)'
            ],
          },
        ],
      };

      // Mock metrics (replace with actual API call if available)
      const metrics = [
        { title: 'Total Score', value: '2,450', change: '+12%', trend: 'up' },
        { title: 'Challenges Completed', value: '42', change: '+5%', trend: 'up' },
        { title: 'Win Rate', value: '78%', change: '+3%', trend: 'up' },
        { title: 'Avg. Time per Challenge', value: '24m', change: '-2m', trend: 'down' },
      ];

      setAnalyticsData({
        performance: performanceData,
        categories: categoriesData,
        teamComparison: teamComparisonData,
        metrics
      });

    } catch (err) {
      console.error('Error fetching analytics:', err);
      setError('Failed to load analytics data. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyticsData(timeRange);
  }, [timeRange]);

  // Mock data for charts
  const performanceData = {
    labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
    datasets: [
      {
        label: 'Your Team',
        data: [65, 78, 82, 90],
        borderColor: 'rgb(75, 192, 192)',
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        tension: 0.3,
        fill: true
      },
      {
        label: 'Average',
        data: [50, 60, 70, 80],
        borderColor: 'rgb(201, 203, 207)',
        borderDash: [5, 5],
        backgroundColor: 'transparent',
        tension: 0.3
      }
    ]
  };

  const categoryData = {
    labels: ['Web Exploits', 'Network Security', 'Forensics', 'Cryptography', 'Reverse Engineering'],
    datasets: [
      {
        label: 'Challenges Completed',
        data: [12, 19, 3, 5, 2],
        backgroundColor: [
          'rgba(255, 99, 132, 0.7)',
          'rgba(54, 162, 235, 0.7)',
          'rgba(255, 206, 86, 0.7)',
          'rgba(75, 192, 192, 0.7)',
          'rgba(153, 102, 255, 0.7)'
        ],
        borderWidth: 1,
      },
    ],
  };

  const teamComparisonData = {
    labels: ['Your Team', 'Top 25%', 'Average', 'Your Rank'],
    datasets: [
      {
        label: 'Score',
        data: [85, 90, 65, 8],
        backgroundColor: [
          'rgba(75, 192, 192, 0.7)',
          'rgba(54, 162, 235, 0.7)',
          'rgba(255, 206, 86, 0.7)',
          'rgba(153, 102, 255, 0.7)'
        ],
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
      },
      title: {
        display: true,
        text: 'Performance Over Time',
      },
    },
  };

  if (isLoading && !analyticsData.performance.labels.length) {
    return (
      <Container className="text-center py-5">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
        <p className="mt-2">Loading analytics...</p>
      </Container>
    );
  }

  if (error) {
    return (
      <Container className="py-4">
        <Alert variant="danger">
          <Alert.Heading>Error Loading Analytics</Alert.Heading>
          <p>{error}</p>
          <Button 
            className="btn btn-outline-danger" 
            onClick={() => fetchAnalyticsData(timeRange)}
          >
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
          <h2>Analytics Dashboard</h2>
          <p className="text-muted">Track your team's performance and statistics</p>
        </Col>
        <Col md={3}>
          <Form.Select 
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
          >
            <option value="week">Last 7 days</option>
            <option value="month">Last 30 days</option>
            <option value="quarter">Last 90 days</option>
            <option value="year">Last Year</option>
            <option value="all">All Time</option>
          </Form.Select>
        </Col>
      </Row>

      <Tabs
        activeKey={activeTab}
        onSelect={(k) => setActiveTab(k)}
        className="mb-4"
      >
        <Tab eventKey="overview" title="Overview">
          <Row className="mt-4">
            <Col lg={8} className="mb-4">
              <Card className="h-100">
                <Card.Body>
                  <div style={{ height: '400px' }}>
                    <Line data={analyticsData.performance} options={chartOptions} />
                  </div>
                </Card.Body>
              </Card>
            </Col>
            <Col lg={4} className="mb-4">
              <Card className="h-100">
                <Card.Body>
                  <h5>Skill Distribution</h5>
                  <div style={{ height: '300px' }}>
                    <Doughnut 
                      data={analyticsData.categories} 
                      options={{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                          legend: {
                            position: 'bottom'
                          }
                        }
                      }} 
                    />
                  </div>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>
        
        <Tab eventKey="comparison" title="Team Comparison">
          <Row className="mt-4">
            <Col lg={12}>
              <Card>
                <Card.Body>
                  <div style={{ height: '400px' }}>
                    <Bar 
                      data={analyticsData.teamComparison} 
                      options={{
                        ...chartOptions,
                        indexAxis: 'y',
                        plugins: {
                          ...chartOptions.plugins,
                          title: {
                            ...chartOptions.plugins.title,
                            text: 'Team Comparison'
                          },
                          legend: {
                            display: false
                          }
                        }
                      }} 
                    />
                  </div>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>
        
        <Tab eventKey="metrics" title="Detailed Metrics">
          <Row className="mt-4">
            {analyticsData.metrics.map((metric, index) => (
              <Col key={index} md={6} lg={3} className="mb-4">
                <Card className="h-100">
                  <Card.Body>
                    <h6 className="text-muted">{metric.title}</h6>
                    <div className="d-flex justify-content-between align-items-center">
                      <h3 className="mb-0">{metric.value}</h3>
                      <span className={`badge bg-${metric.trend === 'up' ? 'success' : 'info'} bg-opacity-10 text-${metric.trend === 'up' ? 'success' : 'info'}`}>
                        {metric.change}
                      </span>
                    </div>
                    <small className="text-muted">vs previous period</small>
                  </Card.Body>
                </Card>
              </Col>
            ))}
          </Row>
        </Tab>
      </Tabs>
    </Container>
  );
};

export default Analytics;
