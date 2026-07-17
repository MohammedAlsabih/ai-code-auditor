// EXPECT-ESLINT: CLEAN (deps complete)
import { useEffect, useState } from 'react';

export function Complete({ q }: { q: string }) {
  const [n] = useState(0);
  useEffect(() => {
    console.log(q, n);
  }, [q, n]);
  return null;
}
