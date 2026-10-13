import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type TrendPoint } from "../api";
import { Card, CardHeader, ErrorMessage, Loading, cx } from "./ui";

/** "2026-10-12" as "Oct 12, 2026", in the viewer's locale. */
function day(value: string) {
  return new Date(value + "T12:00:00Z").toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
}

const ranges = [30, 90, 365] as const;

const series = [
  { key: "critical", label: "Critical", fill: "fill-red-600", swatch: "bg-red-600" },
  { key: "high", label: "High", fill: "fill-orange-500", swatch: "bg-orange-500" },
  { key: "medium", label: "Medium", fill: "fill-amber-400", swatch: "bg-amber-400" },
  { key: "low", label: "Low", fill: "fill-sky-500", swatch: "bg-sky-500" },
  { key: "unknown", label: "Unrated", fill: "fill-slate-400", swatch: "bg-slate-400" },
] as const;

const width = 720;
const height = 200;
const pad = { top: 10, right: 12, bottom: 22, left: 40 };

/**
 * Open vulnerabilities over time, stacked by severity, with those known to be
 * exploited as a line: each host counts with its latest scan on each day.
 */
export function TrendChart({ host, title = "Vulnerabilities over time" }: { host?: string; title?: string }) {
  const [days, setDays] = useState<(typeof ranges)[number]>(90);
  const [tag, setTag] = useState("");
  const tags = useQuery({ queryKey: ["tags"], queryFn: api.tags, enabled: !host });
  const trend = useQuery({ queryKey: ["trends", days, host ?? "", tag], queryFn: () => api.trends(days, { host, tag }) });

  return (
    <Card className="mt-6">
      <CardHeader
        title={title}
        description={
          host
            ? "Open vulnerabilities after each day's latest scan, by severity, and how many are known to be exploited."
            : "Open vulnerabilities on all hosts, each counted from its latest scan on that day, by severity, and how many are known to be exploited."
        }
        action={
          <div className="flex flex-wrap items-center gap-2">
            {!host && (tags.data?.length ?? 0) > 0 && (
              <select
                aria-label="Hosts"
                value={tag}
                onChange={(event) => setTag(event.target.value)}
                className="rounded-lg border-0 bg-white py-1.5 pr-8 pl-3 text-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
              >
                <option value="">All hosts</option>
                {tags.data!.map((item) => (
                  <option key={item.tag} value={item.tag}>
                    Tagged {item.tag} ({item.hosts})
                  </option>
                ))}
              </select>
            )}
            <div className="inline-flex rounded-lg ring-1 ring-slate-300 ring-inset dark:ring-slate-700" role="group" aria-label="Period">
              {ranges.map((range) => (
                <button
                  key={range}
                  type="button"
                  aria-pressed={days === range}
                  onClick={() => setDays(range)}
                  className={cx(
                    "px-3 py-1.5 text-sm first:rounded-l-lg last:rounded-r-lg",
                    days === range
                      ? "bg-slate-900 font-semibold text-white dark:bg-slate-100 dark:text-slate-900"
                      : "text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800",
                  )}
                >
                  {range === 365 ? "1 year" : `${range} days`}
                </button>
              ))}
            </div>
          </div>
        }
      />
      <div className="px-5 py-4">
        {trend.isPending ? (
          <Loading />
        ) : trend.error ? (
          <ErrorMessage error={trend.error} />
        ) : (
          <Chart points={trend.data} />
        )}
      </div>
    </Card>
  );
}

function total(point: TrendPoint) {
  return point.critical + point.high + point.medium + point.low + point.unknown;
}

function Chart({ points }: { points: TrendPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const first = points.findIndex((point) => point.hosts > 0);
  // Start at the first day with results.
  const shown = useMemo(() => (first < 0 ? [] : points.slice(first)), [points, first]);
  const max = useMemo(() => Math.max(1, ...shown.map(total)), [shown]);
  if (shown.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-slate-500 dark:text-slate-400">
        No scan results in this period yet. Each scan that checks packages adds a day.
      </p>
    );
  }
  const plotWidth = width - pad.left - pad.right;
  const plotHeight = height - pad.top - pad.bottom;
  const x = (index: number) => pad.left + (shown.length === 1 ? plotWidth / 2 : (index / (shown.length - 1)) * plotWidth);
  const y = (value: number) => pad.top + plotHeight - (value / max) * plotHeight;

  // Stack the severities: each area runs from the sum below it to the sum including it.
  const bases = shown.map(() => 0);
  const areas = series.map((item) => {
    const tops = shown.map((point, index) => bases[index] + point[item.key]);
    const path =
      tops.map((top, index) => `${index === 0 ? "M" : "L"}${x(index).toFixed(1)},${y(top).toFixed(1)}`).join(" ") +
      " " +
      bases
        .map((base, index) => [index, base] as const)
        .reverse()
        .map(([index, base]) => `L${x(index).toFixed(1)},${y(base).toFixed(1)}`)
        .join(" ") +
      " Z";
    tops.forEach((top, index) => (bases[index] = top));
    return { ...item, path };
  });
  const exploitedLine = shown.map((point, index) => `${index === 0 ? "M" : "L"}${x(index).toFixed(1)},${y(point.exploited).toFixed(1)}`).join(" ");
  const ticks = [0, Math.round(max / 2), max];
  const labels = [0, Math.floor((shown.length - 1) / 2), shown.length - 1];
  const current = shown[hover ?? shown.length - 1];

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-baseline gap-x-5 gap-y-1 text-sm">
        <span className="text-slate-500 dark:text-slate-400">{hover === null ? "Today" : day(current.day)}</span>
        <span>
          <span className="font-semibold tabular-nums">{total(current).toLocaleString()}</span> open on {current.hosts}{" "}
          host{current.hosts === 1 ? "" : "s"}
        </span>
        <span className="text-red-700 dark:text-red-300">
          <span className="font-semibold tabular-nums">{current.exploited.toLocaleString()}</span> known exploited
        </span>
        {series.map((item) => (
          <span key={item.key} className="inline-flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300">
            <span className={cx("size-2.5 rounded-sm", item.swatch)} aria-hidden />
            {item.label} <span className="tabular-nums">{current[item.key].toLocaleString()}</span>
          </span>
        ))}
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-auto w-full"
        role="img"
        aria-label={`Open vulnerabilities over ${shown.length} days, from ${total(shown[0])} to ${total(shown[shown.length - 1])}; known exploited from ${shown[0].exploited} to ${shown[shown.length - 1].exploited}.`}
        onMouseLeave={() => setHover(null)}
        onMouseMove={(event) => {
          const box = event.currentTarget.getBoundingClientRect();
          const position = ((event.clientX - box.left) / box.width) * width;
          const index = Math.round(((position - pad.left) / plotWidth) * (shown.length - 1));
          setHover(Math.min(shown.length - 1, Math.max(0, index)));
        }}
      >
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={pad.left} x2={width - pad.right} y1={y(tick)} y2={y(tick)} className="stroke-slate-200 dark:stroke-slate-800" />
            <text x={pad.left - 6} y={y(tick) + 4} textAnchor="end" className="fill-slate-500 text-[11px] dark:fill-slate-400">
              {tick.toLocaleString()}
            </text>
          </g>
        ))}
        {areas.map((area) => (
          <path key={area.key} d={area.path} className={cx(area.fill, "opacity-85")} />
        ))}
        <path d={exploitedLine} fill="none" strokeWidth={2.5} strokeDasharray="5 3" className="stroke-red-900 dark:stroke-red-300" />
        {labels.map((index) => (
          <text
            key={index}
            x={x(index)}
            y={height - 6}
            textAnchor={index === 0 ? "start" : index === shown.length - 1 ? "end" : "middle"}
            className="fill-slate-500 text-[11px] dark:fill-slate-400"
          >
            {shown[index].day.slice(5)}
          </text>
        ))}
        {hover !== null && (
          <line x1={x(hover)} x2={x(hover)} y1={pad.top} y2={pad.top + plotHeight} className="stroke-slate-500 dark:stroke-slate-400" strokeWidth={1} />
        )}
      </svg>
      <p className="mt-2 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
        <svg width="22" height="6" aria-hidden>
          <line x1="0" x2="22" y1="3" y2="3" strokeWidth="2.5" strokeDasharray="5 3" className="stroke-red-900 dark:stroke-red-300" />
        </svg>
        Known exploited (CISA KEV). Hosts scanned before 0.16.0 count no exploited vulnerabilities until their next scan.
      </p>
    </div>
  );
}
