/** The DeaconGuard mark: the dg monogram in a shield on a navy tile. Kept in
 * step with assets/brand/deaconguard-icon.svg. */
export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} role="img" aria-label="DeaconGuard">
      <rect width="64" height="64" rx="14" fill="#13213a" />
      <g transform="translate(32 32) scale(0.74) translate(-32 -32.5)">
        <path
          d="M32 3 57 11.5V31c0 15.5-11 26-25 31C18 57 7 46.5 7 31V11.5Z"
          fill="none"
          stroke="#ffffff"
          strokeWidth="3.5"
          strokeLinejoin="round"
        />
        <g transform="translate(32 33) scale(0.6) translate(-34 -36)" fill="none" strokeWidth="5" strokeLinecap="round">
          <circle cx="20" cy="36" r="9" stroke="#ffffff" />
          <path d="M29 45V16" stroke="#ffffff" />
          <circle cx="44" cy="36" r="9" stroke="#ffffff" />
          <path d="M53 27v20c0 7-5 10-10 10s-8-2-9.5-5" stroke="#c8912e" />
        </g>
      </g>
    </svg>
  );
}
