/**
 * AnimatedNumber.jsx
 * Drop into: frontend/src/components/AnimatedNumber.jsx
 *
 * Counts up from the previous value to the new `value` prop
 * using a smooth easeOutExpo curve whenever the value changes.
 */
import { useEffect, useRef, useState, memo } from 'react';

function easeOutExpo(t) {
  return t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
}

const AnimatedNumber = memo(function AnimatedNumber({
  value    = 0,
  duration = 2500,   // ms
  suffix   = '+',
}) {
  const [display, setDisplay]   = useState(0);
  const prevValueRef            = useRef(0);
  const rafRef                  = useRef(null);

  useEffect(() => {
    if (value === prevValueRef.current) return;

    const from      = 0;
    const to        = value;
    const startTime = performance.now();
    prevValueRef.current = to;

    function tick(now) {
      const elapsed  = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased    = easeOutExpo(progress);
      setDisplay(Math.round(from + (to - from) * eased));
      if (progress < 1) rafRef.current = requestAnimationFrame(tick);
    }

    cancelAnimationFrame(rafRef.current);
    rafRef.current = requestAnimationFrame(tick);

    return () => cancelAnimationFrame(rafRef.current);
  }, [value, duration]);

  // Format with locale commas: 12847 → "12,847"
  return <span>{display.toLocaleString()}{suffix}</span>;
});

export default AnimatedNumber;