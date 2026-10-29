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
        { type: 'category', label: '1.14', collapsed: true, items: ['upgrade-notes/v1-14/v1-14-0'] },
        { type: 'category', label: '1.13', collapsed: true, items: ['upgrade-notes/v1-13/v1-13-0'] },
        { type: 'category', label: '1.12', collapsed: true, items: ['upgrade-notes/v1-12/v1-12-0'] },
        { type: 'category', label: '1.11', collapsed: true, items: ['upgrade-notes/v1-11/v1-11-1', 'upgrade-notes/v1-11/v1-11-0'] },
        { type: 'category', label: '1.10', collapsed: true, items: ['upgrade-notes/v1-10/v1-10-0'] },
        { type: 'category', label: '1.9', collapsed: true, items: ['upgrade-notes/v1-9/v1-9-2', 'upgrade-notes/v1-9/v1-9-1', 'upgrade-notes/v1-9/v1-9-0'] },
        { type: 'category', label: '1.8', collapsed: true, items: ['upgrade-notes/v1-8/v1-8-1', 'upgrade-notes/v1-8/v1-8-0'] },
        { type: 'category', label: '1.7', collapsed: true, items: ['upgrade-notes/v1-7/v1-7-0'] },
        { type: 'category', label: '1.6', collapsed: true, items: ['upgrade-notes/v1-6/v1-6-0'] },
        { type: 'category', label: '1.5', collapsed: true, items: ['upgrade-notes/v1-5/v1-5-0'] },
      ],
    },
    {
      type: 'category',
      label: 'Using DeaconGuard',
      collapsed: false,
      items: ['usage/server', 'usage/agents', 'usage/vulnerabilities', 'usage/libraries-and-sbom', 'usage/containers', 'usage/images', 'usage/ci-cd', 'usage/config-checks', 'usage/kubernetes', 'usage/network', 'usage/audits', 'usage/compliance', 'usage/policies', 'usage/reports', 'usage/notifications', 'usage/accounts', 'usage/single-sign-on', 'usage/local-mode', 'usage/dashboard', 'usage/backup-and-restore'],
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
