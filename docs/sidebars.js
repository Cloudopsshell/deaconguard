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
      label: 'Using DeaconGuard',
      collapsed: false,
      items: ['usage/server', 'usage/agents', 'usage/vulnerabilities', 'usage/audits', 'usage/compliance', 'usage/policies', 'usage/reports', 'usage/notifications', 'usage/accounts', 'usage/local-mode', 'usage/dashboard', 'usage/backup-and-restore'],
    },
    'checks',
    'supported-distributions',
    'architecture',
    {
      type: 'category',
      label: 'Security',
      items: ['security/securing-the-dashboard', 'security/verify-a-release', 'security/hardening', 'security/reporting'],
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
