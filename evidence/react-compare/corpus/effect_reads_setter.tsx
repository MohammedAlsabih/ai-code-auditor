// EXPECT-ESLINT: CLEAN (useState setter is stable; exhaustive-deps exempts it)
import { useEffect, useState } from 'react';

export function Reset() {
  const [n, setN] = useState(0);
  useEffect(() => {
    setN(0);
  }, []);
  return <p>{n}</p>;
}
