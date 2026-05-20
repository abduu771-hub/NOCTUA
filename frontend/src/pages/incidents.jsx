// src/pages/incidents.jsx
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
  Tab,
  Tooltip,
  Divider,
  Avatar,
  Badge,
  LinearProgress
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
  Visibility as ViewIcon,
  Close as CloseIcon,
  Download as ExportIcon,
  Timeline as TimelineIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Whatshot as WhatshotIcon,
  Bolt as BoltIcon,
  Security as SecurityIcon,
  People as PeopleIcon,
  Devices as DevicesIcon,
  Router as RouterIcon,
  AccountCircle as AccountCircleIcon,
  Schedule as ScheduleIcon,
  TrendingUp as TrendingUpIcon
} from '@mui/icons-material';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip as ChartTooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
  Filler
} from 'chart.js';
import { Bar, Pie, Line } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  ChartTooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
  Filler
);

const API_BASE_URL = 'http://localhost:8000';

// Status colors and labels
const statusConfig = {
  open: { color: '#f44336', label: 'Open', icon: <ErrorIcon sx={{ fontSize: 16 }} /> },
  investigating: { color: '#ff9800', label: 'Investigating', icon: <SearchIcon sx={{ fontSize: 16 }} /> },
  closed: { color: '#4caf50', label: 'Closed', icon: <CheckCircleIcon sx={{ fontSize: 16 }} /> },
  escalated: { color: '#9c27b0', label: 'Escalated', icon: <WhatshotIcon sx={{ fontSize: 16 }} /> }
};

// Incident type icons and colors
const incidentTypeConfig = {
  brute_force_attack: { icon: '🔨', label: 'SSH Brute Force', severity: 'high' },
  password_spray_attack: { icon: '🌧️', label: 'Password Spray', severity: 'high' },
  distributed_bruteforce_attack: { icon: '🌐', label: 'Distributed Brute Force', severity: 'critical' },
  targeted_account_attack: { icon: '🎯', label: 'Targeted Account Attack', severity: 'critical' },
  account_compromise: { icon: '🔥', label: 'Account Compromise', severity: 'critical' },
  privilege_escalation_attempt: { icon: '⬆️', label: 'Privilege Escalation', severity: 'high' },
  default: { icon: '⚠️', label: 'Security Incident', severity: 'medium' }
};

const severityColors = {
  critical: '#f44336',
  high: '#ff9800',
  medium: '#ffc107',
  low: '#2196f3'
};

const IncidentsPage = () => {
  // State for incidents list
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // State for pagination
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [totalIncidents, setTotalIncidents] = useState(0);
  
  // State for overview stats
  const [overview, setOverview] = useState(null);
  
  // State for filters
  const [filters, setFilters] = useState({
    status: '',
    incident_type: '',
    user: '',
    host: '',
    search: ''
  });
  
  // State for selected incident drawer
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [incidentDetails, setIncidentDetails] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [timelineLoading, setTimelineLoading] = useState(false);
  
  // State for chart tab
  const [chartTab, setChartTab] = useState(0);
  
  // State for charts data
  const [incidentsOverTime, setIncidentsOverTime] = useState([]);
  const [typeDistribution, setTypeDistribution] = useState({});
  const [statusDistribution, setStatusDistribution] = useState({});

  // Fetch incidents with filters and pagination
  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const params = new URLSearchParams();
      params.append('size', rowsPerPage);
      
      if (filters.status) params.append('status', filters.status);
      if (filters.incident_type) params.append('incident_type', filters.incident_type);
      if (filters.user) params.append('user', filters.user);
      if (filters.host) params.append('host', filters.host);
      
      const response = await fetch(`${API_BASE_URL}/api/incidents?${params}`);
      if (!response.ok) throw new Error('Failed to fetch incidents');
      
      const data = await response.json();
      
      // Map API response to table format
      const mappedIncidents = data.map(incident => ({
        id: incident._id,
        incident_id: incident.incident?.id || incident._id?.slice(-8),
        type: incident.incident?.incident_type || 'security_incident',
        status: incident.incident?.status || 'open',
        alert_count: incident.incident?.alert_count || 0,
        primary_user: incident.attack_context?.primary_user || incident.attack_context?.users_seen?.[0] || 'Unknown',
        host: incident.host?.name || 'Unknown',
        source_ips: incident.attack_context?.source_ips_seen || [],
        first_seen: incident.created_at,
        last_seen: incident.updated_at,
        version: incident.incident?.version || 1,
        is_escalated: incident.incident?.type === 'account_compromise',
        attack_context: incident.attack_context,
        related: incident.related
      }));
      
      setIncidents(mappedIncidents);
      setTotalIncidents(data.length);
      
      // Calculate chart data
      calculateChartData(mappedIncidents);
      
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [rowsPerPage, filters]);

  // Calculate chart data from incidents
  const calculateChartData = useCallback((incidentsData) => {
    // Type distribution
    const typeCounts = {};
    incidentsData.forEach(inc => {
      const type = inc.type;
      typeCounts[type] = (typeCounts[type] || 0) + 1;
    });
    setTypeDistribution(typeCounts);
    
    // Status distribution
    const statusCounts = {};
    incidentsData.forEach(inc => {
      const status = inc.status;
      statusCounts[status] = (statusCounts[status] || 0) + 1;
    });
    setStatusDistribution(statusCounts);
    
    // Incidents over time (last 7 days)
    const last7days = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      last7days.push(date.toLocaleDateString());
    }
    
    const dailyCounts = last7days.map(day => {
      return incidentsData.filter(inc => {
        const incDate = new Date(inc.first_seen).toLocaleDateString();
        return incDate === day;
      }).length;
    });
    
    setIncidentsOverTime(dailyCounts);
  }, []);

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

  // Fetch incident details
  const fetchIncidentDetails = async (incidentId) => {
    setDetailsLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/incidents/${incidentId}`);
      if (!response.ok) throw new Error('Failed to fetch incident details');
      const data = await response.json();
      setIncidentDetails({
        id: data._id,
        incident_id: data.incident?.id,
        type: data.incident?.incident_type,
        status: data.incident?.status,
        alert_count: data.incident?.alert_count,
        version: data.incident?.version,
        created_at: data.created_at,
        updated_at: data.updated_at,
        attack_context: data.attack_context,
        host: data.host,
        source: data.source,
        related: data.related,
        incident: data.incident
      });
    } catch (err) {
      console.error('Details fetch error:', err);
    } finally {
      setDetailsLoading(false);
    }
  };

  // Fetch timeline
  const fetchTimeline = async (incidentId) => {
    setTimelineLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/incidents/${incidentId}/timeline`);
      if (!response.ok) throw new Error('Failed to fetch timeline');
      const data = await response.json();
      setTimeline(data);
    } catch (err) {
      console.error('Timeline fetch error:', err);
    } finally {
      setTimelineLoading(false);
    }
  };

  // Handle filter change
  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPage(0);
  };

  // Handle refresh
  const handleRefresh = () => {
    fetchIncidents();
    fetchOverview();
  };

  // Handle row click
  const handleRowClick = async (incident) => {
    setSelectedIncident(incident);
    setDrawerOpen(true);
    await fetchIncidentDetails(incident.id);
    await fetchTimeline(incident.id);
  };

  // Clear all filters
  const clearFilters = () => {
    setFilters({
      status: '',
      incident_type: '',
      user: '',
      host: '',
      search: ''
    });
    setPage(0);
  };

  // Get severity for incident type
  const getIncidentSeverity = (type) => {
    return incidentTypeConfig[type]?.severity || 'medium';
  };

  // Format source IPs display
  const formatSourceIPs = (ips) => {
    if (!ips || ips.length === 0) return '-';
    if (ips.length === 1) return ips[0];
    return `${ips[0]} (+${ips.length - 1})`;
  };

  // Initial data load
  useEffect(() => {
    fetchIncidents();
    fetchOverview();
  }, []);

  useEffect(() => {
    fetchIncidents();
  }, [page, rowsPerPage, filters, fetchIncidents]);

  // Chart data
  const typeChartData = {
    labels: Object.keys(typeDistribution).map(t => incidentTypeConfig[t]?.label || t),
    datasets: [{
      label: 'Incidents by Type',
      data: Object.values(typeDistribution),
      backgroundColor: ['#f44336', '#ff9800', '#ffc107', '#2196f3', '#9c27b0', '#4caf50'],
      borderWidth: 1
    }]
  };

  const statusChartData = {
    labels: Object.keys(statusDistribution).map(s => statusConfig[s]?.label || s),
    datasets: [{
      label: 'Incidents by Status',
      data: Object.values(statusDistribution),
      backgroundColor: ['#f44336', '#ff9800', '#4caf50', '#9c27b0'],
      borderWidth: 1
    }]
  };

  const overtimeChartData = {
    labels: (() => {
      const labels = [];
      for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        labels.push(date.toLocaleDateString());
      }
      return labels;
    })(),
    datasets: [{
      label: 'Incidents Over Time',
      data: incidentsOverTime,
      borderColor: '#1a237e',
      backgroundColor: 'rgba(26, 35, 126, 0.1)',
      fill: true,
      tension: 0.4
    }]
  };

  return (
    <>
      <Helmet>
        <title>Incidents | Abur SIEM</title>
      </Helmet>

      <Box sx={{ py: 4, px: 3, bgcolor: '#f5f5f5', minHeight: '100vh' }}>
        <Container maxWidth="xl">
          {/* Header */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
            <Typography variant="h4" sx={{ fontFamily: "'ClashDisplay', sans-serif", fontWeight: 600, color: '#1a237e' }}>
              Incident Investigation Workspace
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
                    <Typography color="textSecondary" gutterBottom>Total Incidents</Typography>
                    <Typography variant="h3" fontWeight="bold">{overview.total_incidents || 0}</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={2.4}>
                <Card sx={{ borderRadius: 3, boxShadow: 2, borderTop: '4px solid #f44336' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Open Incidents</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#f44336">{overview.open_incidents || 0}</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={2.4}>
                <Card sx={{ borderRadius: 3, boxShadow: 2, borderTop: '4px solid #9c27b0' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Active Compromises</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#9c27b0">-</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={2.4}>
                <Card sx={{ borderRadius: 3, boxShadow: 2, borderTop: '4px solid #ff9800' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>High Severity</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#ff9800">-</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} sm={6} md={2.4}>
                <Card sx={{ borderRadius: 3, boxShadow: 2, borderTop: '4px solid #4caf50' }}>
                  <CardContent>
                    <Typography color="textSecondary" gutterBottom>Auto-Closed</Typography>
                    <Typography variant="h3" fontWeight="bold" color="#4caf50">-</Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          )}

          {/* Charts Section */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
            <Tabs value={chartTab} onChange={(e, v) => setChartTab(v)} sx={{ mb: 3 }}>
              <Tab label="Incidents Over Time" />
              <Tab label="Type Distribution" />
              <Tab label="Status Distribution" />
            </Tabs>
            <Box sx={{ height: 350 }}>
              {chartTab === 0 && incidentsOverTime.length > 0 && (
                <Line data={overtimeChartData} options={{ maintainAspectRatio: false, responsive: true }} />
              )}
              {chartTab === 1 && Object.keys(typeDistribution).length > 0 && (
                <Pie data={typeChartData} options={{ maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }} />
              )}
              {chartTab === 2 && Object.keys(statusDistribution).length > 0 && (
                <Bar data={statusChartData} options={{ maintainAspectRatio: false, responsive: true }} />
              )}
              {loading && (
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
                  placeholder="Search by ID, user, host, IP..."
                  value={filters.search}
                  onChange={(e) => handleFilterChange('search', e.target.value)}
                  InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon /></InputAdornment> }}
                />
              </Grid>
              <Grid item xs={6} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Status</InputLabel>
                  <Select value={filters.status} label="Status" onChange={(e) => handleFilterChange('status', e.target.value)}>
                    <MenuItem value="">All</MenuItem>
                    <MenuItem value="open">Open</MenuItem>
                    <MenuItem value="investigating">Investigating</MenuItem>
                    <MenuItem value="closed">Closed</MenuItem>
                    <MenuItem value="escalated">Escalated</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Incident Type</InputLabel>
                  <Select value={filters.incident_type} label="Incident Type" onChange={(e) => handleFilterChange('incident_type', e.target.value)}>
                    <MenuItem value="">All</MenuItem>
                    <MenuItem value="brute_force_attack">SSH Brute Force</MenuItem>
                    <MenuItem value="password_spray_attack">Password Spray</MenuItem>
                    <MenuItem value="distributed_bruteforce_attack">Distributed Brute Force</MenuItem>
                    <MenuItem value="account_compromise">Account Compromise</MenuItem>
                    <MenuItem value="privilege_escalation_attempt">Privilege Escalation</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6} md={2}>
                <TextField fullWidth size="small" label="User" value={filters.user} onChange={(e) => handleFilterChange('user', e.target.value)} />
              </Grid>
              <Grid item xs={6} md={2}>
                <TextField fullWidth size="small" label="Host" value={filters.host} onChange={(e) => handleFilterChange('host', e.target.value)} />
              </Grid>
              <Grid item xs={12} md={1}>
                <Button fullWidth variant="outlined" startIcon={<FilterIcon />} onClick={clearFilters}>
                  Clear
                </Button>
              </Grid>
            </Grid>
          </Paper>

          {/* Incidents Table */}
          <Paper sx={{ borderRadius: 3, overflow: 'hidden' }}>
            <TableContainer>
              <Table>
                <TableHead sx={{ bgcolor: '#1a237e' }}>
                  <TableRow>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Status</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Type</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Primary User</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Host</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Source IPs</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Alert Count</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>First Seen</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Last Seen</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Version</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 600 }}>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={10} align="center" sx={{ py: 8 }}><CircularProgress /></TableCell>
                    </TableRow>
                  ) : error ? (
                    <TableRow>
                      <TableCell colSpan={10} align="center" sx={{ py: 8 }}>
                        <MuiAlert severity="error">{error}</MuiAlert>
                      </TableCell>
                    </TableRow>
                  ) : incidents.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={10} align="center" sx={{ py: 8 }}>No incidents found</TableCell>
                    </TableRow>
                  ) : (
                    incidents.map((incident) => {
                      const severity = getIncidentSeverity(incident.type);
                      return (
                        <TableRow key={incident.id} hover sx={{ cursor: 'pointer' }} onClick={() => handleRowClick(incident)}>
                          <TableCell>
                            <Chip 
                              icon={statusConfig[incident.status]?.icon}
                              label={statusConfig[incident.status]?.label || incident.status}
                              size="small"
                              sx={{ 
                                bgcolor: statusConfig[incident.status]?.color,
                                color: 'white',
                                '& .MuiChip-icon': { color: 'white' }
                              }}
                            />
                          </TableCell>
                          <TableCell>
                            <Tooltip title={incident.type}>
                              <Chip
                                avatar={<Avatar sx={{ bgcolor: severityColors[severity], width: 24, height: 24 }}>{incidentTypeConfig[incident.type]?.icon || '⚠️'}</Avatar>}
                                label={incidentTypeConfig[incident.type]?.label || incident.type}
                                size="small"
                                variant="outlined"
                              />
                            </Tooltip>
                          </TableCell>
                          <TableCell>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <AccountCircleIcon sx={{ fontSize: 16, color: '#1a237e' }} />
                              <Typography variant="body2">{incident.primary_user}</Typography>
                            </Stack>
                          </TableCell>
                          <TableCell>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <DevicesIcon sx={{ fontSize: 16, color: '#1a237e' }} />
                              <Typography variant="body2">{incident.host}</Typography>
                            </Stack>
                          </TableCell>
                          <TableCell>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <RouterIcon sx={{ fontSize: 16, color: '#1a237e' }} />
                              <Typography variant="body2">{formatSourceIPs(incident.source_ips)}</Typography>
                            </Stack>
                          </TableCell>
                          <TableCell>
                            <Badge badgeContent={incident.alert_count} color="error" />
                          </TableCell>
                          <TableCell>
                            <Stack direction="row" spacing={1} alignItems="center">
                              <ScheduleIcon sx={{ fontSize: 14, color: '#78909c' }} />
                              <Typography variant="caption">{new Date(incident.first_seen).toLocaleDateString()}</Typography>
                            </Stack>
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption">{new Date(incident.last_seen).toLocaleDateString()}</Typography>
                          </TableCell>
                          <TableCell>
                            <Chip label={`v${incident.version}`} size="small" variant="outlined" />
                          </TableCell>
                          <TableCell>
                            <IconButton size="small" onClick={(e) => { e.stopPropagation(); handleRowClick(incident); }} title="Investigate">
                              <ViewIcon fontSize="small" />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </TableContainer>
            <TablePagination
              rowsPerPageOptions={[25, 50, 100]}
              component="div"
              count={totalIncidents}
              rowsPerPage={rowsPerPage}
              page={page}
              onPageChange={(e, p) => setPage(p)}
              onRowsPerPageChange={(e) => setRowsPerPage(parseInt(e.target.value, 10))}
            />
          </Paper>
        </Container>
      </Box>

      {/* Incident Detail Drawer */}
      <Drawer 
        anchor="right" 
        open={drawerOpen} 
        onClose={() => setDrawerOpen(false)} 
        sx={{ '& .MuiDrawer-paper': { width: { xs: '100%', sm: 600, md: 700 } } }}
      >
        <Box sx={{ p: 3, height: '100%', overflow: 'auto' }}>
          {/* Header */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 3 }}>
            <Box>
              <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 1 }}>
                {selectedIncident?.is_escalated && (
                  <WhatshotIcon sx={{ color: '#f44336', fontSize: 28 }} />
                )}
                <Typography variant="h5" sx={{ fontFamily: "'ClashDisplay', sans-serif", fontWeight: 600 }}>
                  {incidentTypeConfig[selectedIncident?.type]?.label || 'Security Incident'}
                </Typography>
                <Chip 
                  label={statusConfig[selectedIncident?.status]?.label}
                  sx={{ bgcolor: statusConfig[selectedIncident?.status]?.color, color: 'white' }}
                />
              </Stack>
              <Typography variant="caption" color="textSecondary">
                ID: {selectedIncident?.incident_id || selectedIncident?.id?.slice(-8)}
              </Typography>
              <Box sx={{ display: 'flex', gap: 3, mt: 1 }}>
                <Typography variant="caption" color="textSecondary">
                  First Seen: {selectedIncident?.first_seen ? new Date(selectedIncident.first_seen).toLocaleString() : '-'}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Last Updated: {selectedIncident?.last_seen ? new Date(selectedIncident.last_seen).toLocaleString() : '-'}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Version: {selectedIncident?.version}
                </Typography>
              </Box>
            </Box>
            <IconButton onClick={() => setDrawerOpen(false)}><CloseIcon /></IconButton>
          </Box>

          {detailsLoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}><CircularProgress /></Box>
          ) : incidentDetails ? (
            <Stack spacing={3}>
              {/* Attack Story Section */}
              <Paper sx={{ p: 3, bgcolor: '#fff3e0', borderRadius: 2 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TrendingUpIcon color="warning" /> Attack Evolution
                </Typography>
                <Stack spacing={2}>
                  {timeline.slice(0, 5).map((event, idx) => (
                    <Box key={idx} sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
                      <Box sx={{ minWidth: 100 }}>
                        <Typography variant="caption" color="textSecondary">
                          {new Date(event['@timestamp']).toLocaleTimeString()}
                        </Typography>
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="body2">{event.rule?.description || event.message || 'Event detected'}</Typography>
                        {event.severity && (
                          <Chip label={event.severity} size="small" sx={{ mt: 0.5, bgcolor: severityColors[event.severity?.toLowerCase()], color: 'white' }} />
                        )}
                      </Box>
                    </Box>
                  ))}
                  {timeline.length === 0 && (
                    <Typography variant="body2" color="textSecondary">No timeline events available</Typography>
                  )}
                </Stack>
              </Paper>

              {/* Timeline Section */}
              <Paper sx={{ p: 3, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TimelineIcon color="primary" /> Investigation Timeline
                </Typography>
                {timelineLoading ? (
                  <CircularProgress size={24} />
                ) : timeline.length > 0 ? (
                  <Stack spacing={2}>
                    {timeline.map((event, idx) => (
                      <Box key={idx} sx={{ display: 'flex', gap: 2, alignItems: 'flex-start', p: 1, '&:hover': { bgcolor: '#f5f5f5' } }}>
                        <Box sx={{ minWidth: 160 }}>
                          <Typography variant="caption" color="textSecondary">
                            {new Date(event['@timestamp']).toLocaleString()}
                          </Typography>
                        </Box>
                        <Box sx={{ flex: 1 }}>
                          <Typography variant="body2">{event.rule?.description || event.message || 'Event'}</Typography>
                          {event.source?.ip && (
                            <Typography variant="caption" color="textSecondary">
                              Source IP: {event.source.ip}
                            </Typography>
                          )}
                          {event.user?.name && (
                            <Typography variant="caption" color="textSecondary" sx={{ ml: 2 }}>
                              User: {event.user.name}
                            </Typography>
                          )}
                        </Box>
                      </Box>
                    ))}
                  </Stack>
                ) : (
                  <Typography variant="body2" color="textSecondary">No timeline available</Typography>
                )}
              </Paper>

              {/* Attack Context Panel */}
              <Paper sx={{ p: 3, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                  <SecurityIcon color="secondary" /> Attack Context
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="caption" color="textSecondary">Users Seen</Typography>
                    <Box sx={{ mt: 1 }}>
                      {incidentDetails.attack_context?.users_seen?.map((user, idx) => (
                        <Chip key={idx} icon={<PeopleIcon />} label={user} size="small" sx={{ mr: 1, mb: 1 }} />
                      )) || '-'}
                    </Box>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="caption" color="textSecondary">Source IPs</Typography>
                    <Box sx={{ mt: 1 }}>
                      {incidentDetails.attack_context?.source_ips_seen?.map((ip, idx) => (
                        <Chip key={idx} icon={<RouterIcon />} label={ip} size="small" sx={{ mr: 1, mb: 1 }} />
                      )) || '-'}
                    </Box>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="caption" color="textSecondary">Hosts Seen</Typography>
                    <Box sx={{ mt: 1 }}>
                      {incidentDetails.attack_context?.hosts_seen?.map((host, idx) => (
                        <Chip key={idx} icon={<DevicesIcon />} label={host} size="small" sx={{ mr: 1, mb: 1 }} />
                      )) || '-'}
                    </Box>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="caption" color="textSecondary">Compromised User</Typography>
                    <Typography variant="body2" sx={{ mt: 1, fontWeight: 'bold', color: '#f44336' }}>
                      {incidentDetails.attack_context?.compromised_user || '-'}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="caption" color="textSecondary">Grouping Strategy</Typography>
                    <Chip 
                      label={incidentDetails.attack_context?.grouping_strategy || 'unknown'} 
                      size="small" 
                      color="primary" 
                      sx={{ mt: 1 }}
                    />
                  </Grid>
                </Grid>
              </Paper>

              {/* Related Alerts Section */}
              <Paper sx={{ p: 3, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                  <WarningIcon color="error" /> Related Alerts
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  {incidentDetails.related?.rule_ids?.map((ruleId, idx) => (
                    <Chip key={idx} label={ruleId} variant="outlined" size="small" />
                  )) || <Typography variant="body2" color="textSecondary">No related alerts</Typography>}
                  {incidentDetails.alert_count > 0 && (
                    <Typography variant="caption" color="textSecondary" sx={{ mt: 1 }}>
                      Total alerts associated: {incidentDetails.alert_count}
                    </Typography>
                  )}
                </Box>
              </Paper>
            </Stack>
          ) : (
            <Typography>No details available</Typography>
          )}
        </Box>
      </Drawer>
    </>
  );
};

export default IncidentsPage;