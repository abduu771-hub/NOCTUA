import { Outlet } from 'react-router-dom';
import { Layout as DashboardLayout } from './layouts/dashboard/layout';
import OverviewPage from './pages/overview';
import AlertsPage from './pages/alerts';
import IncidentsPage from './pages/incidents';
import DevicesPage from './pages/devices';
import UsersPage from './pages/users';
import LogsPage from './pages/logs';
import ThreatIntelPage from './pages/threat-intel';
import SettingsPage from './pages/settings';
import LandingPage from './pages/index';
import NotFoundPage from './pages/404';

export const routes = [
  {
    element: (
      <DashboardLayout>
        <Outlet />
      </DashboardLayout>
    ),
    children: [
      {
          path: '/',
           element: <LandingPage />
      },
      {
        path: 'overview',
        element: <OverviewPage />
      },
      {
        path: 'alerts',
        element: <AlertsPage />
      },
      {
        path: 'incidents',
        element: <IncidentsPage />
      },
      {
        path: 'devices',
        element: <DevicesPage />
      },
      {
        path: 'users',
        element: <UsersPage />
      },
      {
        path: 'logs',
        element: <LogsPage />
      },
      {
        path: 'threat-intel',
        element: <ThreatIntelPage />
      },
      {
        path: 'settings',
        element: <SettingsPage />
      }
    ]
  },
  {
    path: '404',
    element: <NotFoundPage />
  },
  {
    path: '*',
    element: <NotFoundPage />
  }
];