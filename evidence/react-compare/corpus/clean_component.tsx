// EXPECT-ESLINT: CLEAN (well-formed component, complete deps)
import { useState, useEffect } from 'react';

export function Widget({ q }: { q: string }) {
  const [v, setV] = useState(0);
  useEffect(() => { console.log(q); }, [q]);
  return <div onClick={() => setV(v + 1)}>{v}</div>;
}
