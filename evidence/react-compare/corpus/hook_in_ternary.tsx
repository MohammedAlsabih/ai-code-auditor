// EXPECT-ESLINT: rules-of-hooks ERROR (hook called conditionally via ternary)
import { useMemo } from 'react';

export function TernaryBad({ flag }: { flag: boolean }) {
  const v = flag ? useMemo(() => 1, []) : 0;
  return <p>{v}</p>;
}
