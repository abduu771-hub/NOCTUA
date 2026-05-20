// src/pages/alerts.jsx
import React, { useState, useEffect, useCallback } from 'react';
import { Helmet } from 'react-helmet-async';
import {
  Box,
  Container,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  IconButton,
  TextField,
  InputAdornment,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Button,
  Grid,
  Card,
  CardContent,
  Drawer,
  Stack,
  CircularProgress,
  Alert as MuiAlert,
  Tabs,
  Tab
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
  Visibility as ViewIcon,
  Close as CloseIcon,
  Download as ExportIcon
} from '@mui/icons-material';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement
} from 'chart.js';
import { Bar, Pie, Line } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement
);

const API_BASE_URL = 'http://localhost:8000';

const severityColors = {
  low: '#2196f3',
  medium: '#ffc107',
  high: '#ff9800',
  critical: '#f44336',
  Low: '#2196f3',
  Medium: '#ffc107',
  High: '#ff9800',
  Critical: '#f44336'
};

const AlertsPage = () => {
  // State for alerts list
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // State for pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalAlerts, setTotalAlerts] = useState(0);
  
  // State for overview stats
  const [overview, setOverview] = useState(null);
  
  // State for charts data (calculated from alerts)
  const [severityStats, setSeverityStats] = useState(null);
  const [trendData, setTrendData] = useState([]);
  const [topDevices, setTopDevices] = useState([]);
  
  // State for filters
  const [filters, setFilters] = useState({
    severity: '',
    host: '',
    user: '',
    source_ip: '',
    search: ''
  });
  
  // State for selected alert detail drawer
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [alertDetails, setAlertDetails] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  
  // State for chart tab
  const [chartTab, setChartTab] = useState(0);

  // Calculate statistics from alerts data
  const calculateStats = useCallback((alertsData) => {
    // Severity counts
    const severityCounts = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0
    };
    
    // Device counts
    const deviceMap = new Map();
    
    alertsData.forEach(alert => {
      const severity = (alert.rule?.severity || 'medium').toLowerCase();
      if (severityCounts[severity] !== undefined) {
        severityCounts[severity]++;
      } else {
        severityCounts.medium++;
      }
      
      const host = alert.host?.name || alert.source?.ip || 'unknown';
      deviceMap.set(host, (deviceMap.get(host) || 0) + 1);
    });
    
    setSeverityStats(severityCounts);
    
    // Top devices
    const sortedDevices = Array.from(deviceMap.entries())
      .map(([device, count]) => ({ device, alert_count: count }))
      .sort((a, b) => b.alert_count - a.alert_count)
      .slice(0, 5);
    setTopDevices(sortedDevices);
    
    // Trend data (last 24 hours)
    const now = new Date();
    const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const hourlyData = new Array(24).fill(0);
    
    alertsData.forEach(alert => {
      const timestamp = new Date(alert['@timestamp']);
      if (timestamp >= last24h) {
        const hour = timestamp.getHours();
        hourlyData[hour]++;
      }
    });
    
    const trend = hourlyData.map((count, hour) => ({
      timestamp: `${hour}:00`,
      count
    }));
    setTrendData(trend);
  }, []);

  // Fetch alerts with filters and pagination
  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const params = new URLSearchParams();
      params.append('size', rowsPerPage);
      
      if (filters.severity) params.append('severity', filters.severity.toLowerCase());
      if (filters.host) params.append('host', filters.host);
      if (filters.user) params.append('user', filters.user);
      if (filters.source_ip) params.append('source_ip', filters.source_ip);
      
      const response = await fetch(`${API_BASE_URL}/api/alerts?${params}`);
      if (!response.ok) throw new Error('Failed to fetch alerts');
      
      const data = await response.json();
      
      // Map API response to table format
      const mappedAlerts = data.map(alert => ({
        id: alert._id,
        type: alert.rule?.name || alert.rule?.description || 'Security Alert',
        severity: alert.rule?.severity || 'Medium',
        source_ip: alert.source?.ip || alert.host?.name || 'Unknown',
        user: alert.user?.name || 'System',
        timestamp: alert['@timestamp'],
        status: 'active', // Default status, can be enhanced
        linked_incident_id: alert.correlation?.incident_id,
        host: alert.host?.name,
        rule: alert.rule,
        message: alert.message || alert.rule?.description
      }));
      
      setAlerts(mappedAlerts);
      setTotalAlerts(data.length);
      
      // Calculate charts from fetched data
      calculateStats(data);
      
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [rowsPerPage, filters, calculateStats]);

  // Fetch overview stats
  const fetchOverview = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/overview`);
      if (!response.ok) throw new Error('Failed to fetch overview');
      const data = await response.json();
      setOverview(data);
    } catch (err) {
      console.error('Overview fetch error:', err);
    }
  }, []);

  // Fetch alert details for drawer
  const fetchAlertDetails = async (alertId) => {
    setDetailsLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/alerts/${alertId}`);
      if (!response.ok) throw new Error('Failed to fetch alert details');
      const data = await response.json();
      setAlertDetails({
        id: data._id,
        type: data.rule?.name || data.rule?.description,
        severity: data.rule?.severity,
        message: data.message || data.rule?.description,
        source_ip: data.source?.ip,
        device: data.host?.name,
        user: data.user?.name,
        timestamp: data['@timestamp'],
        status: 'active',
        rule: data.rule,
        event: data.event,
        mitre: data.mitre
      });
    } catch (err) {
      console.error('Details fetch error:', err);
    } finally {
      setDetailsLoading(false);
    }
  };

  // Handle filter change
  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPage(0);
  };

  // Handle refresh
  const handleRefresh = () => {
    fetchAlerts();
    fetchOverview();
  };

  // Handle row click
  const handleRowClick = (alert) => {
    setSelectedAlert(alert);
    fetchAlertDetails(alert.id);
    setDrawerOpen(true);
  };

  // Clear all filters
  const clearFilters = () => {
    setFilters({
      severity: '',
      host: '',
      user: '',
      source_ip: '',
      search: ''
    });
    setPage(0);
  };

  // Initial data load
  useEffect(() => {
    fetchAlerts();
    fetchOverview();
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [page, rowsPerPage, filters, fetchAlerts]);

  // Prepare chart data
  const severityChartData = severityStats ? {
    labels: ['Low', 'Medium', 'High', 'Critical'],
    datasets: [{
      label: 'Alerts by Severity',
      data: [severityStats.low, severityStats.medium, severityStats.high, severityStats.critical],
      backgroundColor: ['#2196f3', '#ffc107', '#ff9800', '#f44336'],
      borderColor: ['#1976d2', '#ffa000', '#f57c00', '#d32f2f'],
      borderWidth: 1
    }]
  } : null;

  const trendChartData = trendData.length > 0 ? {
    labels: trendData.map(d => d.timestamp),
    datasets: [{
      label: 'Alerts per Hour',
      data: trendData.map(d => d.count),
      borderColor: '#1a237e',
      backgroundColor: 'rgba(26, 35, 126, 0.1)',
      fill: true,
      tension: 0.4
    }]
  } : null;

  const topDevicesChartData = topDevices.length > 0 ? {
    labels: topDevices.map(d => d.device),
    datasets: [{
      label: 'Alerts by Device',
      data: topDevices.map(d => d.alert_count),
      backgroundColor: '#1a237e',
      borderRadius: 8
    }]
  } : null;

  return (
    <>
      <Helmet>
        <title>Alerts | Abur SIEM</title>
      </Helmet>

      <Box sx={{ py: 4, px: 3, bgcolor: '#f5f5f5', minHeight: '100vh' }}>
        <Container maxWidth="xl">
          {/* Header */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
            <Typography variant="h4" sx={{ fontFamily: "'ClashDisplay', sans-serif", fontWeight: 600, color: '#1a237e' }}>
              Alerts
            </Typography>
            <Box sx={{ display: 'flex', gap: 2 }}>
              <Button
                variant="outlined"
                startIcon={<ExportIcon />}
                sx={{ borderRadius: 2, borderColor: '#1a237e', color: '#1a237e' }}
              >
                Export
              </Button>
              <Button
                variant="contained"
                startIcon={<RefreshIcon />}
                onClick={handleRefresh}
                sx={{ borderRadius: 2, bgcolor: '#1a237e', '&:hover': { bgcolor: '#0d47a1' } }}
              >
                Refresh
              </Button>
            </Box>
          </Box>

          {/* KPI Cards */}
          {overview && (
            <Grid container spacing={3} sx={{ mb: 4 }}>
              <Grid item xs={12} sm={6} md={2.4}>
                <Card sx={{ borderRadius: 3, boxShadow: 2 }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Total Alerts</Typography>
                    <Typography variant="h3" fontWeight="bold">{overview.total_alerts || 0}</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={2.4}>
                <Card sx={{ borderRadius: 3, boxShadow: 2, borderTop: '4px solid #f44336' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Critical</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#f44336">{overview.critical_alerts || 0}</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={2.4}>
                <Card sx={{ borderRadius: 3, boxShadow: 2, borderTop: '4px solid #ff9800' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Total Incidents</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#ff9800">{overview.total_incidents || 0}</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={2.4}>
                <Card sx={{ borderRadius: 3, boxShadow: 2, borderTop: '4px solid #ffc107' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Open Incidents</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#ffc107">{overview.open_incidents || 0}</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={2.4}>
                <Card sx={{ borderRadius: 3, boxShadow: 2, borderTop: '4px solid #2196f3' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Total Events</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#2196f3">{overview.total_events || 0}</Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          )}

          {/* Charts Section */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
            <Tabs value={chartTab} onChange={(e, v) => setChartTab(v)} sx={{ mb: 3 }}>
              <Tab label="Severity Distribution" />
              <Tab label="Trend (24h)" />
              <Tab label="Top Devices" />
            </Tabs>
            <Box sx={{ height: 350 }}>
              {chartTab === 0 && severityChartData && (
                <Pie data={severityChartData} options={{ maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }} />
              )}
              {chartTab === 1 && trendChartData && (
                <Line data={trendChartData} options={{ maintainAspectRatio: false, responsive: true }} />
              )}
              {chartTab === 2 && topDevicesChartData && (
                <Bar data={topDevicesChartData} options={{ maintainAspectRatio: false, responsive: true }} />
              )}
              {(!severityChartData || (!trendChartData.length && chartTab === 1) || (!topDevicesChartData && chartTab === 2)) && loading && (
                <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
                  <CircularProgress />
                </Box>
              )}
            </Box>
          </Paper>

          {/* Filters */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={3}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Search by keyword..."
                  value={filters.search}
                  onChange={(e) => handleFilterChange('search', e.target.value)}
                  InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon /></InputAdornment> }}
                />
              </Grid>
              <Grid item xs={6} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Severity</InputLabel>
                  <Select value={filters.severity} label="Severity" onChange={(e) => handleFilterChange('severity', e.target.value)}>
                    <MenuItem value="">All</MenuItem>
                    <MenuItem value="low">Low</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6} md={2}>
                <TextField fullWidth size="small" label="Host" value={filters.host} onChange={(e) => handleFilterChange('host', e.target.value)} />
              </Grid>
              <Grid item xs={6} md={2}>
                <TextField fullWidth size="small" label="User" value={filters.user} onChange={(e) => handleFilterChange('user', e.target.value)} />
              </Grid>
              <Grid item xs={6} md={2}>
                <TextField fullWidth size="small" label="Source IP" value={filters.source_ip} onChange={(e) => handleFilterChange('source_ip', e.target.value)} />
              </Grid>
              <Grid item xs={12} md={1}>
                <Button fullWidth variant="outlined" startIcon={<FilterIcon />} onClick={clearFilters}>
                  Clear
                </Button>
              </Grid>
            </Grid>
          </Paper>

          {/* Alerts Table */}
          <Paper sx={{ borderRadius: 3, overflow: 'hidden' }}>
            <TableContainer>
              <Table>
                <TableHead sx={{ bgcolor: '#1a237e' }}>
                  <TableRow>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>ID</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Type</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Severity</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Source</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>User</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Timestamp</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center" sx={{ py: 8 }}><CircularProgress /></TableCell>
                    </TableRow>
                  ) : error ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center" sx={{ py: 8 }}>
                        <MuiAlert severity="error">{error}</MuiAlert>
                      </TableCell>
                    </TableRow>
                  ) : alerts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center" sx={{ py: 8 }}>No alerts found</TableCell>
                    </TableRow>
                  ) : (
                    alerts.map((alert) => (
                      <TableRow key={alert.id} hover sx={{ cursor: 'pointer' }} onClick={() => handleRowClick(alert)}>
                        <TableCell>{alert.id.slice(-8)}</TableCell>
                        <TableCell>{alert.type}</TableCell>
                        <TableCell>
                          <Chip label={alert.severity} size="small" sx={{ bgcolor: severityColors[alert.severity], color: 'white' }} />
                        </TableCell>
                        <TableCell>{alert.source_ip}</TableCell>
                        <TableCell>{alert.user}</TableCell>
                        <TableCell>{new Date(alert.timestamp).toLocaleString()}</TableCell>
                        <TableCell>
                          <IconButton size="small" onClick={(e) => { e.stopPropagation(); handleRowClick(alert); }} title="View Details">
                            <ViewIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>
            <TablePagination
              rowsPerPageOptions={[25, 50, 100]}
              component="div"
              count={totalAlerts}
              rowsPerPage={rowsPerPage}
              page={page}
              onPageChange={(e, p) => setPage(p)}
              onRowsPerPageChange={(e) => setRowsPerPage(parseInt(e.target.value, 10))}
            />
          </Paper>
        </Container>
      </Box>

      {/* Alert Detail Drawer */}
      <Drawer anchor="right" open={drawerOpen} onClose={() => setDrawerOpen(false)} sx={{ '& .MuiDrawer-paper': { width: { xs: '100%', sm: 500 } } }}>
        <Box sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h5" sx={{ fontFamily: "'ClashDisplay', sans-serif" }}>Alert Details</Typography>
            <IconButton onClick={() => setDrawerOpen(false)}><CloseIcon /></IconButton>
          </Box>
          {detailsLoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}><CircularProgress /></Box>
          ) : alertDetails ? (
            <Stack spacing={2}>
              <Paper sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                <Typography variant="subtitle2" color="textSecondary">Alert ID</Typography>
                <Typography variant="body1">{alertDetails.id}</Typography>
              </Paper>
              <Paper sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                <Typography variant="subtitle2" color="textSecondary">Type</Typography>
                <Typography variant="body1">{alertDetails.type}</Typography>
              </Paper>
              <Paper sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                <Typography variant="subtitle2" color="textSecondary">Severity</Typography>
                <Chip label={alertDetails.severity} sx={{ bgcolor: severityColors[alertDetails.severity], color: 'white' }} />
              </Paper>
              <Paper sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                <Typography variant="subtitle2" color="textSecondary">Message</Typography>
                <Typography variant="body1">{alertDetails.message}</Typography>
              </Paper>
              <Paper sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                <Typography variant="subtitle2" color="textSecondary">Source</Typography>
                <Typography variant="body1">{alertDetails.source_ip}</Typography>
              </Paper>
              <Paper sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                <Typography variant="subtitle2" color="textSecondary">Device</Typography>
                <Typography variant="body1">{alertDetails.device}</Typography>
              </Paper>
              <Paper sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                <Typography variant="subtitle2" color="textSecondary">User</Typography>
                <Typography variant="body1">{alertDetails.user}</Typography>
              </Paper>
              <Paper sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                <Typography variant="subtitle2" color="textSecondary">Timestamp</Typography>
                <Typography variant="body1">{new Date(alertDetails.timestamp).toLocaleString()}</Typography>
              </Paper>
              {alertDetails.rule && (
                <Paper sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                  <Typography variant="subtitle2" color="textSecondary">Rule Info</Typography>
                  <Typography variant="body2">ID: {alertDetails.rule.id}</Typography>
                  <Typography variant="body2">Description: {alertDetails.rule.description}</Typography>
                </Paper>
              )}
              {alertDetails.mitre && (
                <Paper sx={{ p: 2, bgcolor: '#f5f5f5' }}>
                  <Typography variant="subtitle2" color="textSecondary">MITRE ATT&CK</Typography>
                  <Typography variant="body2">Tactics: {alertDetails.mitre.tactics?.join(', ')}</Typography>
                  <Typography variant="body2">Techniques: {alertDetails.mitre.techniques?.join(', ')}</Typography>
                </Paper>
              )}
            </Stack>
          ) : (
            <Typography>No details available</Typography>
          )}
        </Box>
      </Drawer>
    </>
  );
};

export default AlertsPage;