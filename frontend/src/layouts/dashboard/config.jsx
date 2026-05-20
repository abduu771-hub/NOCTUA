// src/layouts/dashboard/config.js
import {
  BellAlertIcon,
  ShieldExclamationIcon,
  ChartBarIcon,
  ComputerDesktopIcon,
  UsersIcon,
  DocumentTextIcon,
  ServerStackIcon,
  Cog6ToothIcon
} from '@heroicons/react/24/solid';
import { SvgIcon } from '@mui/material';

export const items = [
  {
    href: '/overview',
    icon: (
      <SvgIcon>
        <ChartBarIcon />
      </SvgIcon>
    ),
    label: 'Overview'
  },
  {
    href: '/alerts',
    icon: (
      <SvgIcon>
        <BellAlertIcon />
      </SvgIcon>
    ),
    label: 'Alerts'
  },
  {
    href: '/incidents',
    icon: (
      <SvgIcon>
        <ShieldExclamationIcon />
      </SvgIcon>
    ),
    label: 'Incidents'
  },
  {
    href: '/devices',
    icon: (
      <SvgIcon>
        <ComputerDesktopIcon />
      </SvgIcon>
    ),
    label: 'Devices'
  },
  {
    href: '/users',
    icon: (
      <SvgIcon>
        <UsersIcon />
      </SvgIcon>
    ),
    label: 'Users'
  },
  {
    href: '/logs',
    icon: (
      <SvgIcon>
        <DocumentTextIcon />
      </SvgIcon>
    ),
    label: 'Logs'
  },
  {
    href: '/threat-intel',
    icon: (
      <SvgIcon>
        <ServerStackIcon />
      </SvgIcon>
    ),
    label: 'Threat Intel'
  },
  {
    href: '/settings',
    icon: (
      <SvgIcon>
        <Cog6ToothIcon />
      </SvgIcon>
    ),
    label: 'Settings'
  }
];