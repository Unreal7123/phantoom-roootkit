// ============================================================================
// PhantomScope — GraphView.tsx
// BloodHound-style Directed Graph with Cytoscape.js
// ============================================================================

import React, { useEffect, useRef, useState, useCallback } from 'react';
import cytoscape, { Core, NodeSingular, EventObject } from 'cytoscape';
import coseBilkent from 'cytoscape-cose-bilkent';
import { useScanStore, GraphElement } from '../store/scanStore';
import { QueryBar }    from './QueryBar';
import { ContextMenu } from './ContextMenu';

// Register CoSE-Bilkent layout
cytoscape.use(coseBilkent as any);

// ============================================================================
// Cytoscape stylesheet
// ============================================================================
const GRAPH_STYLESHEET: cytoscape.Stylesheet[] = [
  {
    selector: 'node',
    style: {
      'width':              50,
      'height':             50,
      'background-color':   'data(color)',
      'label':              'data(name)',
      'font-family':        '"JetBrains Mono", "Fira Code", monospace',
      'font-size':          '11px',
      'font-weight':        '500',
      'color':              '#EBEBF5',
      'text-valign':        'bottom',
      'text-halign':        'center',
      'text-margin-y':      6,
      'text-max-width':     '120px',
      'text-wrap':          'ellipsis',
      'border-width':       2,
      'border-color':       'data(color)',
      'border-opacity':     0.4,
      'background-opacity': 0.9,
      'shadow-blur':        12,
      'shadow-color':       'data(color)',
      'shadow-opacity':     0.6,
      'shadow-offset-x':    0,
      'shadow-offset-y':    0,
      'transition-property': 'background-color, border-color, shadow-blur, width, height',
      'transition-duration': '0.2s',
    }
  },
  {
    selector: 'node[type="PHHiddenProcess"]',
    style: {
      'width':          64,
      'height':         64,
      'border-width':   3,
      'border-color':   '#FF2D55',
      'border-style':   'dashed',
      'shadow-blur':    20,
      'shadow-opacity': 0.9,
    }
  },
  {
    selector: 'node[type="PHProcess"]',
    style: {
      'shape': 'ellipse',
    }
  },
  {
    selector: 'node[type="PHFile"]',
    style: {
      'shape': 'rectangle',
      'corner-radius': 4,
      'width':  44,
      'height': 44,
    }
  },
  {
    selector: 'node[type="PHService"]',
    style: {
      'shape': 'diamond',
      'width':  48,
      'height': 48,
    }
  },
  {
    selector: 'node[type="PHDriver"]',
    style: {
      'shape': 'hexagon',
      'width':  52,
      'height': 52,
    }
  },
  {
    selector: 'node:selected',
    style: {
      'border-width':   4,
      'border-color':   '#FFFFFF',
      'border-opacity': 1.0,
      'shadow-blur':    24,
      'shadow-opacity': 1.0,
      'width':          function(ele: NodeSingular) { return (ele.style('width') as number) * 1.2; },
      'height':         function(ele: NodeSingular) { return (ele.style('height') as number) * 1.2; },
    }
  },
  {
    selector: 'node.faded',
    style: {
      'opacity': 0.25,
    }
  },
  {
    selector: 'node.highlighted',
    style: {
      'border-width':   3,
      'border-color':   '#FFFFFF',
      'opacity':        1.0,
    }
  },
  {
    // Edges
    selector: 'edge',
    style: {
      'width':               1.5,
      'line-color':          '#3A3A4A',
      'target-arrow-color':  '#3A3A4A',
      'target-arrow-shape':  'triangle',
      'arrow-scale':         1.2,
      'curve-style':         'bezier',
      'opacity':             0.7,
      'label':               '',
      'font-size':           '10px',
      'color':               '#636366',
      'text-background-opacity': 0.7,
      'text-background-color':   '#0A0A0F',
      'text-background-padding': '2px',
      'transition-property': 'opacity, line-color',
      'transition-duration': '0.2s',
    }
  },
  {
    selector: 'edge[type="PHHijackPath"]',
    style: {
      'line-color':          '#FF9F0A',
      'target-arrow-color':  '#FF9F0A',
      'line-style':          'dashed',
      'width':               2,
      'opacity':             0.9,
    }
  },
  {
    selector: 'edge[type="PHInjects"]',
    style: {
      'line-color':          '#FF2D55',
      'target-arrow-color':  '#FF2D55',
      'line-style':          'dashed',
      'width':               2.5,
      'opacity':             0.9,
    }
  },
  {
    selector: 'edge[type="PHSpawnsProcess"]',
    style: {
      'line-color':          '#0A84FF',
      'target-arrow-color':  '#0A84FF',
      'width':               2,
      'opacity':             0.8,
    }
  },
  {
    selector: 'edge:selected',
    style: {
      'line-color':          '#FFFFFF',
      'target-arrow-color':  '#FFFFFF',
      'width':               2.5,
      'label':               'data(label)',
      'opacity':             1.0,
    }
  },
  {
    selector: 'edge.faded',
    style: { 'opacity': 0.08 }
  },
];

// ============================================================================
// GraphView Component
// ============================================================================
export const GraphView: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef        = useRef<Core | null>(null);

  const {
    graphData, filterLevel, searchQuery,
    selectNode, selectedNode, graphLayoutName
  } = useScanStore();

  const [contextMenu, setContextMenu] = useState<{
    x: number; y: number; nodeData: GraphElement['data'];
  } | null>(null);

  const [edgeTooltip, setEdgeTooltip] = useState<{
    x: number; y: number; label: string; type: string;
  } | null>(null);

  // ---- Initialize Cytoscape ----
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container:       containerRef.current,
      elements:        [],
      style:           GRAPH_STYLESHEET,
      layout:          { name: 'preset' },
      minZoom:         0.1,
      maxZoom:         5.0,
      wheelSensitivity: 0.3,
      boxSelectionEnabled: true,
    });

    cyRef.current = cy;

    // Node: single click → select and open inspector
    cy.on('tap', 'node', (evt: EventObject) => {
      const node = evt.target;
      const data = node.data();

      selectNode({ id: data.id, data });
      useScanStore.getState().setActiveView('inspector');

      // Highlight connected neighborhood
      cy.elements().addClass('faded');
      node.removeClass('faded').addClass('highlighted');
      node.connectedEdges().removeClass('faded');
      node.connectedEdges().connectedNodes().removeClass('faded').addClass('highlighted');
    });

    // Node: double click → reveal in OS file manager
    cy.on('dblclick', 'node', (evt: EventObject) => {
      const data = evt.target.data();
      if (data.path) {
        const api = (window as any).phantomAPI;
        api?.openFileInExplorer(data.path);
      }
    });

    // Background tap → clear selection
    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        cy.elements().removeClass('faded highlighted');
        selectNode(null);
        setContextMenu(null);
      }
    });

    // Right click → context menu
    cy.on('cxttap', 'node', (evt: EventObject) => {
      evt.preventDefault();
      const pos = evt.renderedPosition;
      setContextMenu({
        x: pos.x,
        y: pos.y,
        nodeData: evt.target.data(),
      });
    });

    // Edge hover → tooltip
    cy.on('mouseover', 'edge', (evt: EventObject) => {
      const pos = evt.renderedPosition;
      const data = evt.target.data();
      setEdgeTooltip({
        x: pos.x,
        y: pos.y,
        label: data.label || data.type,
        type:  data.type,
      });
    });

    cy.on('mouseout', 'edge', () => setEdgeTooltip(null));

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  // ---- Load graph elements when data changes ----
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graphData) return;

    cy.startBatch();
    cy.elements().remove();

    // Load all elements
    const elements = [
      ...graphData.elements.nodes,
      ...graphData.elements.edges,
    ];
    cy.add(elements as any);

    cy.endBatch();

    // Apply layout
    const layout = cy.layout({
      name: graphLayoutName,
      animate: true,
      animationDuration: 600,
      randomize: false,
      nodeRepulsion: 8000,
      idealEdgeLength: 100,
      edgeElasticity: 0.45,
      gravity: 0.25,
      numIter: 2500,
      tile: true,
      tilingPaddingVertical: 10,
      tilingPaddingHorizontal: 10,
      gravityRangeCompound: 1.5,
      gravityCompound: 1.0,
      gravityRange: 3.8,
      initialEnergyOnIncremental: 0.5,
    } as any);
    layout.run();

    // Fit view after layout
    setTimeout(() => {
      cy.fit(undefined, 40);
    }, 700);

  }, [graphData, graphLayoutName]);

  // ---- Apply search filter ----
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass('faded highlighted');

    if (!searchQuery) return;

    const query = searchQuery.toLowerCase();

    // Parse Cypher-style queries: MATCH (n:PHHiddenProcess) RETURN n
    if (query.startsWith('match')) {
      const typeMatch = query.match(/:\s*([a-z0-9]+)\s*\)/i);
      if (typeMatch) {
        const filterType = typeMatch[1].toLowerCase();
        cy.nodes().forEach(node => {
          const nodeType = (node.data('type') || '').toLowerCase();
          if (!nodeType.includes(filterType)) {
            node.addClass('faded');
          } else {
            node.addClass('highlighted');
          }
        });
        return;
      }
    }

    // Text search: match against name, path, md5
    cy.nodes().forEach(node => {
      const name = (node.data('name') || '').toLowerCase();
      const path = (node.data('path') || '').toLowerCase();
      const md5  = (node.data('md5')  || '').toLowerCase();

      if (!name.includes(query) && !path.includes(query) && !md5.includes(query)) {
        node.addClass('faded');
      } else {
        node.addClass('highlighted');
      }
    });
  }, [searchQuery]);

  // ---- Apply threat level filter ----
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass('faded');

    if (filterLevel === 'all') return;

    cy.nodes().forEach(node => {
      if (node.data('threatLevel') !== filterLevel) {
        node.addClass('faded');
      }
    });
  }, [filterLevel]);

  const handleFitView = useCallback(() => {
    cyRef.current?.fit(undefined, 40);
  }, []);

  const handleResetLayout = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const layout = cy.layout({ name: graphLayoutName, animate: true } as any);
    layout.run();
  }, [graphLayoutName]);

  const handleExportPNG = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const png = cy.png({ full: true, scale: 2, bg: '#0A0A0F' });
    const a = document.createElement('a');
    a.href = png;
    a.download = 'phantomscope-graph.png';
    a.click();
  }, []);

  const hasData = !!(graphData?.elements.nodes.length);

  return (
    <div className="graph-view">
      {/* Query bar */}
      <QueryBar />

      {/* Toolbar */}
      <div className="graph-toolbar">
        <div className="toolbar-group">
          <button className="toolbar-btn" onClick={handleFitView} title="Fit to view (F)">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M1 1h4v2H3v2H1V1zm10 0h4v4h-2V3h-2V1zM1 11h2v2h2v2H1v-4zm12 2h-2v-2h2v-2h2v4h-2z" fill="currentColor"/>
            </svg>
          </button>
          <button className="toolbar-btn" onClick={handleResetLayout} title="Reset layout">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M8 2a6 6 0 100 12A6 6 0 008 2zM2 8a6 6 0 1112 0A6 6 0 012 8z" fill="currentColor"/>
              <path d="M8 5v3.5l2.5 1.5-1 1.7L6.5 10V5H8z" fill="currentColor"/>
            </svg>
          </button>
          <button className="toolbar-btn" onClick={handleExportPNG} title="Export as PNG">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M8 1v9M5 7l3 3 3-3M2 12v2a1 1 0 001 1h10a1 1 0 001-1v-2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" fill="none"/>
            </svg>
          </button>
        </div>

        <div className="toolbar-group toolbar-legend">
          <span className="legend-item legend-critical">CRITICAL</span>
          <span className="legend-item legend-suspicious">SUSPICIOUS</span>
          <span className="legend-item legend-info">INFO</span>
          <span className="legend-item legend-clean">CLEAN</span>
        </div>

        {hasData && (
          <div className="toolbar-stats">
            <span>{graphData!.stats.totalNodes} nodes</span>
            <span>{graphData!.stats.totalEdges} edges</span>
            {graphData!.stats.hiddenProcesses > 0 && (
              <span className="stat-hidden">
                ⚠ {graphData!.stats.hiddenProcesses} hidden
              </span>
            )}
          </div>
        )}
      </div>

      {/* Cytoscape container */}
      <div
        ref={containerRef}
        className="graph-canvas"
      />

      {/* Empty state */}
      {!hasData && (
        <div className="graph-empty-state">
          <div className="empty-icon">
            <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
              <circle cx="40" cy="40" r="38" stroke="#1C1C28" strokeWidth="2"/>
              <circle cx="20" cy="40" r="8" fill="#1C1C28"/>
              <circle cx="40" cy="20" r="8" fill="#1C1C28"/>
              <circle cx="60" cy="40" r="8" fill="#1C1C28"/>
              <circle cx="40" cy="60" r="8" fill="#1C1C28"/>
              <path d="M28 40h12M40 28v12M48 40h12M40 48v12" stroke="#2C2C3E" strokeWidth="1.5"/>
              <circle cx="20" cy="40" r="3" fill="#0A84FF"/>
              <circle cx="40" cy="20" r="3" fill="#30D158"/>
              <circle cx="60" cy="40" r="3" fill="#FF9F0A"/>
              <circle cx="40" cy="60" r="3" fill="#30D158"/>
            </svg>
          </div>
          <h3>No scan data</h3>
          <p>Run a scan to visualize process relationships, file dependencies, and threat indicators.</p>
          <button
            className="btn-primary"
            onClick={() => useScanStore.getState().startScan()}
          >
            Start Scan
          </button>
        </div>
      )}

      {/* Edge tooltip */}
      {edgeTooltip && (
        <div
          className="edge-tooltip"
          style={{ left: edgeTooltip.x + 10, top: edgeTooltip.y - 30 }}
        >
          <span className="edge-type">{edgeTooltip.type}</span>
          <span className="edge-label">{edgeTooltip.label}</span>
        </div>
      )}

      {/* Context menu */}
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          nodeData={contextMenu.nodeData}
          onClose={() => setContextMenu(null)}
        />
      )}
    </div>
  );
};
