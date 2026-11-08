import { useMemo, useRef, useState } from 'react'
import { theme, Typography } from 'antd'

export interface Line {
  name: string
  color: string
  points: [number, number][] // [unix seconds, value]
}

const W = 600

/** A compact time-series chart: lines, a light grid, the latest values and
 * a hover readout. Gaps longer than three buckets break the line. */
export function LineChart({ lines, height = 110, unit = '', digits = 1, min = 0, max, bucket = 360 }: { lines: Line[]; height?: number; unit?: string; digits?: number; min?: number; max?: number; bucket?: number }) {
  const { token } = theme.useToken()
  const ref = useRef<SVGSVGElement>(null)
  const [hover, setHover] = useState<number | null>(null)
  const all = lines.flatMap((l) => l.points)
  const { x0, x1, yMax } = useMemo(() => {
    const xs = all.map((p) => p[0])
    const top = Math.max(max ?? 0, ...all.map((p) => p[1]), min + 1e-9)
    return { x0: Math.min(...xs), x1: Math.max(...xs), yMax: max ?? niceCeil(top) }
  }, [all.length, all[0]?.[0], all[all.length - 1]?.[0], max, min])
  if (!all.length) return <Typography.Text type="secondary">Данных пока нет — они копятся раз в минуту</Typography.Text>
  const pad = 2
  const x = (t: number) => (x1 === x0 ? W / 2 : ((t - x0) / (x1 - x0)) * (W - 2 * pad) + pad)
  const y = (v: number) => height - 4 - ((v - min) / (yMax - min || 1)) * (height - 12)
  const path = (pts: [number, number][]) =>
    pts
      .map((p, i) => `${i === 0 || p[0] - pts[i - 1][0] > bucket * 3 ? 'M' : 'L'}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`)
      .join(' ')
  const fmt = (v: number) => `${v.toFixed(digits)}${unit}`
  const onMove = (e: React.MouseEvent) => {
    const r = ref.current!.getBoundingClientRect()
    const t = x0 + ((e.clientX - r.left) / r.width) * (x1 - x0)
    setHover(t)
  }
  const nearest = (l: Line, t: number) => l.points.reduce((a, p) => (Math.abs(p[0] - t) < Math.abs(a[0] - t) ? p : a), l.points[0])
  return (
    <div style={{ position: 'relative' }}>
      <svg ref={ref} viewBox={`0 0 ${W} ${height}`} preserveAspectRatio="none" width="100%" height={height} onMouseMove={onMove} onMouseLeave={() => setHover(null)} style={{ display: 'block', cursor: 'crosshair' }}>
        {[0.25, 0.5, 0.75].map((f) => (
          <line key={f} x1={0} x2={W} y1={y(min + (yMax - min) * f)} y2={y(min + (yMax - min) * f)} stroke={token.colorBorderSecondary} strokeDasharray="3 4" vectorEffect="non-scaling-stroke" />
        ))}
        {lines.map((l) => l.points.length > 0 && <path key={l.name} d={path(l.points)} fill="none" stroke={l.color} strokeWidth={1.6} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />)}
        {hover !== null && <line x1={x(hover)} x2={x(hover)} y1={0} y2={height} stroke={token.colorTextQuaternary} vectorEffect="non-scaling-stroke" />}
      </svg>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: token.colorTextTertiary, marginTop: 2 }}>
        <span>{time(x0, x1 - x0)}</span>
        <span>макс. {fmt(yMax)}</span>
        <span>{time(x1, x1 - x0)}</span>
      </div>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', fontSize: 12, marginTop: 2 }}>
        {lines.map((l) => {
          if (!l.points.length) return null
          const p = hover !== null ? nearest(l, hover) : l.points[l.points.length - 1]
          return (
            <span key={l.name}>
              <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 2, background: l.color, marginRight: 4 }} />
              {l.name}: <b>{fmt(p[1])}</b>
              {hover !== null && <span style={{ color: token.colorTextTertiary }}> · {time(p[0], 0)}</span>}
            </span>
          )
        })}
      </div>
    </div>
  )
}

function niceCeil(v: number) {
  if (v <= 0) return 1
  const p = Math.pow(10, Math.floor(Math.log10(v)))
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * p) return m * p
  return 10 * p
}

function time(t: number, span: number) {
  const d = new Date(t * 1000)
  return span > 36 * 3600 ? d.toLocaleDateString([], { day: '2-digit', month: '2-digit' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
