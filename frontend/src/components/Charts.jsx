function maxValue(data, keys) {
  return Math.max(1, ...data.flatMap((item) => keys.map((key) => Number(item[key] || 0))));
}

export function LineChart({ data, keys }) {
  const width = 620;
  const height = 240;
  const pad = 34;
  const max = maxValue(data, keys);
  const colors = ['#216869', '#c1121f'];

  function points(key) {
    if (data.length === 1) {
      const y = height - pad - (Number(data[0][key] || 0) / max) * (height - pad * 2);
      return `${pad},${y} ${width - pad},${y}`;
    }
    return data
      .map((item, index) => {
        const x = pad + (index / Math.max(1, data.length - 1)) * (width - pad * 2);
        const y = height - pad - (Number(item[key] || 0) / max) * (height - pad * 2);
        return `${x},${y}`;
      })
      .join(' ');
  }

  return (
    <svg className="chart" viewBox={`0 0 ${width} ${height}`} role="img">
      <line x1={pad} y1={height - pad} x2={width - pad} y2={height - pad} />
      <line x1={pad} y1={pad} x2={pad} y2={height - pad} />
      {keys.map((key, index) => (
        <polyline key={key} points={points(key)} fill="none" stroke={colors[index]} strokeWidth="4" />
      ))}
      {data.map((item, index) => (
        <text key={item.label} x={pad + (index / Math.max(1, data.length - 1)) * (width - pad * 2)} y={height - 8}>
          {item.label.slice(-5)}
        </text>
      ))}
    </svg>
  );
}

export function BarChart({ data, valueKey }) {
  const width = 620;
  const height = 240;
  const pad = 34;
  const max = maxValue(data, [valueKey]);
  const barWidth = data.length ? (width - pad * 2) / data.length - 10 : 26;

  return (
    <svg className="chart" viewBox={`0 0 ${width} ${height}`} role="img">
      <line x1={pad} y1={height - pad} x2={width - pad} y2={height - pad} />
      {data.map((item, index) => {
        const value = Number(item[valueKey] || 0);
        const barHeight = (value / max) * (height - pad * 2);
        const x = pad + index * (barWidth + 10);
        const y = height - pad - barHeight;
        return (
          <g key={item.label}>
            <rect x={x} y={y} width={Math.max(10, barWidth)} height={barHeight} rx="4" />
            <text x={x} y={height - 8}>
              {item.label.slice(-5)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export function PieChart({ data }) {
  const total = Math.max(1, data.reduce((sum, item) => sum + Number(item.value || 0), 0));
  let start = 0;
  const colors = ['#c1121f', '#216869'];

  function segment(value) {
    const angle = (value / total) * Math.PI * 2;
    const end = start + angle;
    const large = angle > Math.PI ? 1 : 0;
    const r = 84;
    const x1 = 120 + r * Math.cos(start);
    const y1 = 120 + r * Math.sin(start);
    const x2 = 120 + r * Math.cos(end);
    const y2 = 120 + r * Math.sin(end);
    const path = `M 120 120 L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`;
    start = end;
    return path;
  }

  return (
    <div className="pie-layout">
      <svg className="pie-chart" viewBox="0 0 240 240" role="img">
        {data.map((item, index) => (
          <path key={item.label} d={segment(Number(item.value || 0))} fill={colors[index]} />
        ))}
      </svg>
      <div className="pie-legend">
        {data.map((item, index) => (
          <span key={item.label}>
            <i style={{ background: colors[index] }} />
            {item.label}: {item.value}
          </span>
        ))}
      </div>
    </div>
  );
}

