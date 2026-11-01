/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
module.exports = {
  docs: [
    'index',
    'quick-start',
    {
      type: 'category',
      label: 'Installation',
      collapsed: false,
      items: [
        'installation/requirements',
        'installation/install-script',
        'installation/manual-install',
        'installation/docker',
        'installation/kubernetes',
        'installation/upgrade',
        'installation/uninstall',
      ],
    },
    {
      type: 'category',
      label: 'Upgrade notes',
      link: { type: 'doc', id: 'upgrade-notes/index' },
      items: [
        { type: 'category', label: '1.23', collapsed: true, items: ['upgrade-notes/v1-23/v1-23-0'] },
        { type: 'category', label: '1.22', collapsed: true, items: ['upgrade-notes/v1-22/v1-22-0'] },
        { type: 'category', label: '1.21', collapsed: true, items: ['upgrade-notes/v1-21/v1-21-0'] },
        { type: 'category', label: '1.20', collapsed: true, items: ['upgrade-notes/v1-20/v1-20-3', 'upgrade-notes/v1-20/v1-20-2', 'upgrade-notes/v1-20/v1-20-1', 'upgrade-notes/v1-20/v1-20-0'] },
        { type: 'category', label: '1.19', collapsed: true, items: ['upgrade-notes/v1-19/v1-19-0'] },
        { type: 'category', label: '1.18', collapsed: true, items: ['upgrade-notes/v1-18/v1-18-0'] },
        { type: 'category', label: '1.17', collapsed: true, items: ['upgrade-notes/v1-17/v1-17-1', 'upgrade-notes/v1-17/v1-17-0'] },
        { type: 'category', label: '1.16', collapsed: true, items: ['upgrade-notes/v1-16/v1-16-0'] },
        { type: 'category', label: '1.15', collapsed: true, items: ['upgrade-notes/v1-15/v1-15-0'] },
        { type: 'category', label: '1.14', collapsed: true, items: ['upgrade-notes/v1-14/v1-14-0'] },
      ],
    },
    {
      type: 'category',
      label: 'Using DeaconGuard',
      collapsed: false,
      items: ['usage/server', 'usage/agents', 'usage/vulnerabilities', 'usage/libraries-and-sbom', 'usage/containers', 'usage/images', 'usage/ci-cd', 'usage/config-checks', 'usage/host-changes', 'usage/kubernetes', 'usage/network', 'usage/audits', 'usage/compliance', 'usage/policies', 'usage/reports', 'usage/notifications', 'usage/accounts', 'usage/single-sign-on', 'usage/local-mode', 'usage/dashboard', 'usage/backup-and-restore'],
    },
    'checks',
    'supported-distributions',
    'architecture',
    {
      type: 'category',
      label: 'Security',
      items: ['security/securing-the-dashboard', 'security/agent-network', 'security/verify-a-release', 'security/hardening', 'security/reporting'],
    },
    {
      type: 'category',
      label: 'Reference',
      items: ['reference/cli', 'reference/api', 'reference/environment', 'reference/files-and-ports'],
    },
    'versioning',
    'faq',
  ],
};
