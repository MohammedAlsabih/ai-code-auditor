// EXPECT-ESLINT: exhaustive-deps WARN (deps array [q] missing state var 'n')
import { useEffect, useState } from 'react';

export function Counter({ q }: { q: string }) {
  const [n, setN] = useState(0);
  useEffect(() => {
    console.log(q, n);
  }, [q]);
  return <button onClick={() => setN(n + 1)}>{n}</button>;
}
