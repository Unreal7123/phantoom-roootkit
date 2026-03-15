// ============================================================================
// PhantomScope — Dashboard.tsx
// Analytics Dashboard with D3.js Charts
// ============================================================================

import React, { useEffect, useRef, useMemo } from 'react';
import * as d3 from 'd3';
import { useScanStore, ScannedFile, ThreatLevel } from '../store/scanStore';

interface DashboardProps {
  showHistory?: boolean;
}

// ---- Entropy Histogram ----
const EntropyHistogram: React.FC<{
  files: ScannedFile[];
}> = ({ files }) => {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current || !files.length) return;

    const W = svgRef.current.clientWidth || 400;
    const H = 180;
    const M = { top: 12, right: 16, bottom: 36, left: 40 };
    const IW = W - M.left - M.right;
    const IH = H - M.top - M.bottom;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const g = svg.append('g')
      .attr('transform', `translate(${M.left},${M.top})`);

    // Entropy values from files
    const values = files.map(f => f.entropy || 0);

    const x = d3.scaleLinear().domain([0, 8]).range([0, IW]);

    // D3 histogram
    const histogram = d3.bin()
      .domain([0, 8])
      .thresholds(32);

    const bins = histogram(values);

    const y = d3.scaleLinear()
      .domain([0, d3.max(bins, d => d.length) || 1])
      .range([IH, 0]);

    // Color function based on entropy threshold
    const barColor = (d: d3.Bin<number, number>) => {
      const mid = ((d.x0 || 0) + (d.x1 || 0)) / 2;
      if (mid > 7.5) return '#FF2D55';
      if (mid > 6.5) return '#FF9F0A';
      return '#0A84FF';
    };

    // Threshold lines
    [6.5, 7.5].forEach((thresh, i) => {
      const colors = ['#FF9F0A', '#FF2D55'];
      g.append('line')
        .attr('x1', x(thresh)).attr('x2', x(thresh))
        .attr('y1', 0).attr('y2', IH)
        .attr('stroke', colors[i])
        .attr('stroke-width', 1)
        .attr('stroke-dasharray', '4,2')
        .attr('opacity', 0.7);

      g.append('text')
        .attr('x', x(thresh) + 3)
        .attr('y', 10)
        .text(thresh.toString())
        .attr('fill', colors[i])
        .attr('font-size', '9px')
        .attr('font-family', 'JetBrains Mono, monospace');
    });

    // Bars
    g.selectAll('rect')
      .data(bins)
      .join('rect')
        .attr('x', d => x(d.x0 || 0) + 1)
        .attr('y', d => y(d.length))
        .attr('width', d => Math.max(0, x(d.x1 || 0) - x(d.x0 || 0) - 2))
        .attr('height', d => IH - y(d.length))
        .attr('fill', barColor)
        .attr('opacity', 0.85)
        .attr('rx', 2);

    // X axis
    g.append('g')
      .attr('transform', `translate(0,${IH})`)
      .call(d3.axisBottom(x).ticks(8).tickSize(3))
      .call(g => {
        g.select('.domain').attr('stroke', '#2C2C3E');
        g.selectAll('.tick line').attr('stroke', '#2C2C3E');
        g.selectAll('.tick text')
          .attr('fill', '#636366')
          .attr('font-size', '10px')
          .attr('font-family', 'JetBrains Mono, monospace');
      });

    // Y axis
    g.append('g')
      .call(d3.axisLeft(y).ticks(4).tickSize(3))
      .call(g => {
        g.select('.domain').attr('stroke', '#2C2C3E');
        g.selectAll('.tick line').attr('stroke', '#2C2C3E');
        g.selectAll('.tick text')
          .attr('fill', '#636366')
          .attr('font-size', '10px')
          .attr('font-family', 'JetBrains Mono, monospace');
      });

    // X label
    g.append('text')
      .attr('x', IW / 2)
      .attr('y', IH + 28)
      .attr('text-anchor', 'middle')
      .attr('fill', '#636366')
      .attr('font-size', '10px')
      .text('Shannon Entropy');

  }, [files]);

  if (!files.length) {
    return (
      <div className="chart-empty">
        <span>No file data available</span>
      </div>
    );
  }

  return (
    <svg ref={svgRef} width="100%" height={180} className="d3-chart" />
  );
};

// ---- VT Detection Timeline ----
const VTTimeline: React.FC<{
  files: ScannedFile[];
}> = ({ files }) => {
  const svgRef = useRef<SVGSVGElement>(null);

  const detectedFiles = useMemo(() =>
    files.filter(f => f.vtDetections > 0)
      .sort((a, b) => (b.vtDetections || 0) - (a.vtDetections || 0))
      .slice(0, 20),
    [files]
  );

  useEffect(() => {
    if (!svgRef.current || !detectedFiles.length) return;

    const W  = svgRef.current.clientWidth || 400;
    const H  = 200;
    const M  = { top: 12, right: 16, bottom: 60, left: 45 };
    const IW = W - M.left - M.right;
    const IH = H - M.top - M.bottom;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const g = svg.append('g').attr('transform', `translate(${M.left},${M.top})`);

    const names = detectedFiles.map(f => {
      const parts = (f.path || '').split(/[/\\]/);
      return parts[parts.length - 1] || f.path;
    });

    const x = d3.scaleBand().domain(names).range([0, IW]).padding(0.3);
    const y = d3.scaleLinear()
      .domain([0, d3.max(detectedFiles, d => d.vtDetections) || 1])
      .range([IH, 0]);

    // Bars
    g.selectAll('rect')
      .data(detectedFiles)
      .join('rect')
        .attr('x', (_, i) => x(names[i]) || 0)
        .attr('y', d => y(d.vtDetections))
        .attr('width', x.bandwidth())
        .attr('height', d => IH - y(d.vtDetections))
        .attr('fill', '#FF2D55')
        .attr('opacity', 0.85)
        .attr('rx', 2);

    // Detection count labels
    g.selectAll('text.bar-label')
      .data(detectedFiles)
      .join('text')
        .attr('class', 'bar-label')
        .attr('x', (_, i) => (x(names[i]) || 0) + x.bandwidth() / 2)
        .attr('y', d => y(d.vtDetections) - 4)
        .attr('text-anchor', 'middle')
        .attr('fill', '#FF2D55')
        .attr('font-size', '9px')
        .attr('font-family', 'JetBrains Mono, monospace')
        .text(d => d.vtDetections);

    // X axis with rotated labels
    g.append('g')
      .attr('transform', `translate(0,${IH})`)
      .call(d3.axisBottom(x).tickSize(0))
      .call(g => {
        g.select('.domain').attr('stroke', '#2C2C3E');
        g.selectAll('.tick text')
          .attr('fill', '#636366')
          .attr('font-size', '9px')
          .attr('font-family', 'JetBrains Mono, monospace')
          .attr('transform', 'rotate(-35)')
          .style('text-anchor', 'end');
      });

    // Y axis
    g.append('g')
      .call(d3.axisLeft(y).ticks(5).tickSize(3))
      .call(g => {
        g.select('.domain').attr('stroke', '#2C2C3E');
        g.selectAll('.tick line').attr('stroke', '#2C2C3E');
        g.selectAll('.tick text')
          .attr('fill', '#636366')
          .attr('font-size', '10px')
          .attr('font-family', 'JetBrains Mono, monospace');
      });

  }, [detectedFiles]);

  if (!detectedFiles.length) {
    return (
      <div className="chart-empty clean-state">
        <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
          <circle cx="16" cy="16" r="14" fill="#30D15820"/>
          <path d="M10 16l4 4 8-8" stroke="#30D158" strokeWidth="2" strokeLinecap="round"/>
        </svg>
        <span>No VirusTotal detections</span>
      </div>
    );
  }

  return (
    <svg ref={svgRef} width="100%" height={200} className="d3-chart" />
  );
};

// ---- Stat Card ----
const StatCard: React.FC<{
  label: string;
  value: number | string;
  sublabel?: string;
  variant?: 'critical' | 'warning' | 'info' | 'clean';
  icon?: React.ReactNode;
}> = ({ label, value, sublabel, variant = 'info', icon }) => {
  const colorMap = {
    critical: '#FF2D55',
    warning:  '#FF9F0A',
    info:     '#0A84FF',
    clean:    '#30D158',
  };

  return (
    <div className={`stat-card stat-${variant}`}
         style={{ '--accent': colorMap[variant] } as React.CSSProperties}>
      <div className="stat-card-header">
        {icon && <div className="stat-icon">{icon}</div>}
        <span className="stat-label">{label}</span>
      </div>
      <div className="stat-value" style={{ color: colorMap[variant] }}>
        {value}
      </div>
      {sublabel && <div className="stat-sublabel">{sublabel}</div>}
    </div>
  );
};

// ---- Threat Leaderboard ----
const ThreatLeaderboard: React.FC<{
  files: ScannedFile[];
}> = ({ files }) => {
  const topFiles = useMemo(() =>
    [...files]
      .filter(f => f.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 15),
    [files]
  );

  const threatColor: Record<ThreatLevel, string> = {
    critical:      '#FF2D55',
    suspicious:    '#FF9F0A',
    informational: '#0A84FF',
    clean:         '#30D158',
  };

  if (!topFiles.length) {
    return (
      <div className="leaderboard-empty">
        <p>No threat indicators found</p>
      </div>
    );
  }

  return (
    <div className="threat-leaderboard">
      {topFiles.map((file, idx) => {
        const name = (file.path || '').split(/[/\\]/).pop() || file.path;
        return (
          <div key={file.path} className="leaderboard-row"
               onClick={() => {
                 useScanStore.getState().selectNode({
                   id: `file-${file.path}`,
                   data: {
                     id: `file-${file.path}`,
                     type: 'PHFile',
                     name, path: file.path, md5: file.md5,
                     entropy: file.entropy, vtDetections: file.vtDetections,
                     isSigned: file.isSigned, score: file.score,
                     threatLevel: file.threatLevel as ThreatLevel,
                     color: threatColor[file.threatLevel as ThreatLevel] || '#636366',
                   }
                 });
                 useScanStore.getState().setActiveView('inspector');
               }}>
            <span className="leaderboard-rank">#{idx + 1}</span>
            <div className="leaderboard-info">
              <span className="leaderboard-name">{name}</span>
              <span className="leaderboard-path">{file.path}</span>
            </div>
            <div className="leaderboard-badges">
              {file.vtDetections > 0 && (
                <span className="badge badge-vt">VT:{file.vtDetections}</span>
              )}
              {file.entropy > 6.5 && (
                <span className="badge badge-entropy">H:{file.entropy.toFixed(1)}</span>
              )}
              {!file.isSigned && (
                <span className="badge badge-unsigned">UNSIGNED</span>
              )}
            </div>
            <div className="leaderboard-score"
                 style={{ color: threatColor[file.threatLevel as ThreatLevel] || '#636366' }}>
              {file.score}
            </div>
          </div>
        );
      })}
    </div>
  );
};

// ============================================================================
// Dashboard — Main Component
// ============================================================================
export const Dashboard: React.FC<DashboardProps> = ({ showHistory = false }) => {
  const { processResult, fileResult, graphData, lastScanTime } = useScanStore();

  const stats = graphData?.stats;
  const files = fileResult?.files || [];

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>
          {showHistory ? 'Scan History' : 'Threat Dashboard'}
        </h1>
        {lastScanTime && (
          <span className="last-scan-time">
            Last scan: {new Date(lastScanTime).toLocaleTimeString()}
          </span>
        )}
      </div>

      {/* Stat cards row */}
      <div className="stat-cards-grid">
        <StatCard
          label="Hidden Processes"
          value={processResult?.hiddenCount ?? '—'}
          sublabel="Rootkit indicators"
          variant={processResult?.hiddenCount ? 'critical' : 'clean'}
          icon={
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <circle cx="9" cy="9" r="7" stroke="currentColor" strokeWidth="1.5"/>
              <path d="M9 5v4.5l3 1.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
              <path d="M4 4l10 10" stroke="#FF2D55" strokeWidth="1.5" strokeLinecap="round" opacity="0.7"/>
            </svg>
          }
        />
        <StatCard
          label="VT Detections"
          value={fileResult?.vtDetectedCount ?? '—'}
          sublabel="Files flagged by antivirus"
          variant={fileResult?.vtDetectedCount ? 'critical' : 'clean'}
          icon={
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <path d="M9 2L2 7v9h14V7L9 2z" stroke="currentColor" strokeWidth="1.5" fill="none"/>
              <path d="M9 8v4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
              <circle cx="9" cy="14" r="0.75" fill="currentColor"/>
            </svg>
          }
        />
        <StatCard
          label="High Entropy"
          value={fileResult?.highEntropyCount ?? '—'}
          sublabel="Likely packed / encrypted"
          variant={fileResult?.highEntropyCount ? 'warning' : 'clean'}
          icon={
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <path d="M2 14L6 8l4 4 4-6 2 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
            </svg>
          }
        />
        <StatCard
          label="Critical Nodes"
          value={stats?.criticalCount ?? '—'}
          sublabel="In graph (score ≥ 70)"
          variant={stats?.criticalCount ? 'critical' : 'clean'}
          icon={
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <circle cx="9" cy="9" r="7" stroke="currentColor" strokeWidth="1.5"/>
              <path d="M9 6v4" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              <circle cx="9" cy="12.5" r="0.75" fill="currentColor"/>
            </svg>
          }
        />
        <StatCard
          label="Suspicious"
          value={stats?.suspiciousCount ?? '—'}
          sublabel="Needs investigation"
          variant={stats?.suspiciousCount ? 'warning' : 'clean'}
        />
        <StatCard
          label="Total Processes"
          value={processResult?.kernelCount ?? '—'}
          sublabel={`${processResult?.usermodeCount ?? 0} user-mode visible`}
          variant="info"
        />
      </div>

      {/* Charts row */}
      <div className="dashboard-charts">
        <div className="chart-card">
          <div className="chart-header">
            <h3>Entropy Distribution</h3>
            <span className="chart-sub">Shannon entropy across {files.length} scanned files</span>
          </div>
          <EntropyHistogram files={files} />
          <div className="chart-legend">
            <span style={{ color: '#0A84FF' }}>■ Normal</span>
            <span style={{ color: '#FF9F0A' }}>■ &gt;6.5 Packed</span>
            <span style={{ color: '#FF2D55' }}>■ &gt;7.5 Encrypted</span>
          </div>
        </div>

        <div className="chart-card">
          <div className="chart-header">
            <h3>VirusTotal Detections</h3>
            <span className="chart-sub">Detection count per file</span>
          </div>
          <VTTimeline files={files} />
        </div>
      </div>

      {/* Threat Leaderboard */}
      <div className="dashboard-leaderboard">
        <div className="leaderboard-header">
          <h3>Top Threats</h3>
          <span className="chart-sub">Sorted by threat score</span>
        </div>
        <ThreatLeaderboard files={files} />
      </div>
    </div>
  );
};
