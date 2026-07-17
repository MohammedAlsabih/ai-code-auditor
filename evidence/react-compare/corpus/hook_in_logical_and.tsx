// EXPECT-ESLINT: rules-of-hooks ERROR (hook called conditionally via && short-circuit)
import { useMemo } from 'react';

export function AndBad({ flag }: { flag: boolean }) {
  const v = flag && useMemo(() => 1, []);
  return <p>{v}</p>;
}
