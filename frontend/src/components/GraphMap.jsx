import * as d3 from 'd3';
import { useEffect, useRef } from 'react';

function GraphMap({ graph }) {
  const svgRef = useRef(null);
  const wrapRef = useRef(null);

  useEffect(() => {
    const nodes = (graph?.nodes || []).map((node) => ({ ...node }));
    const edges = (graph?.edges || []).map((edge) => ({ ...edge }));
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = wrapRef.current?.clientWidth || 960;
    const height = 460;
    svg.attr('viewBox', `0 0 ${width} ${height}`);

    if (nodes.length === 0) {
      svg
        .append('text')
        .attr('x', width / 2)
        .attr('y', height / 2)
        .attr('text-anchor', 'middle')
        .attr('class', 'graph-empty')
        .text('Graph appears after an analysis run');
      return;
    }

    const layer = svg.append('g');
    svg.call(
      d3
        .zoom()
        .scaleExtent([0.35, 3])
        .on('zoom', (event) => {
          layer.attr('transform', event.transform);
        }),
    );

    const link = layer
      .append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(edges)
      .join('line')
      .attr('stroke-width', (edge) => Math.max(1, edge.risk / 35));

    const labels = layer
      .append('g')
      .attr('class', 'edge-labels')
      .selectAll('text')
      .data(edges)
      .join('text')
      .text((edge) => edge.label);

    const node = layer
      .append('g')
      .attr('class', 'nodes')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .attr('tabindex', 0)
      .on('click', (_, item) => {
        if (item.url) {
          window.open(item.url, '_blank', 'noopener,noreferrer');
        }
      });

    node.append('circle').attr('r', (item) => (item.type === 'analysis' ? 22 : 14)).attr('fill', (item) => item.color);
    node
      .append('text')
      .attr('x', 18)
      .attr('y', 5)
      .text((item) => item.label);

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        'link',
        d3
          .forceLink(edges)
          .id((item) => item.id)
          .distance((edge) => 105 + Math.min(90, edge.risk)),
      )
      .force('charge', d3.forceManyBody().strength(-430))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(46));

    function dragged(event, item) {
      item.fx = event.x;
      item.fy = event.y;
    }

    function dragStarted(event, item) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      item.fx = item.x;
      item.fy = item.y;
    }

    function dragEnded(event, item) {
      if (!event.active) simulation.alphaTarget(0);
      item.fx = null;
      item.fy = null;
    }

    node.call(d3.drag().on('start', dragStarted).on('drag', dragged).on('end', dragEnded));

    simulation.on('tick', () => {
      link
        .attr('x1', (edge) => edge.source.x)
        .attr('y1', (edge) => edge.source.y)
        .attr('x2', (edge) => edge.target.x)
        .attr('y2', (edge) => edge.target.y);
      labels
        .attr('x', (edge) => (edge.source.x + edge.target.x) / 2)
        .attr('y', (edge) => (edge.source.y + edge.target.y) / 2);
      node.attr('transform', (item) => `translate(${item.x},${item.y})`);
    });

    return () => simulation.stop();
  }, [graph]);

  return (
    <div className="graph-wrap" ref={wrapRef}>
      <svg ref={svgRef} aria-label="Interactive fraud relationship graph" />
    </div>
  );
}

export default GraphMap;

