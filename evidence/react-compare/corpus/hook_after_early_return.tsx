// EXPECT-ESLINT: rules-of-hooks ERROR (hook called after a conditional early return)
import { useState } from 'react';

export function EarlyReturn({ ready }: { ready: boolean }) {
  if (!ready) return null;
  const [v] = useState(0);
  return <p>{v}</p>;
}
