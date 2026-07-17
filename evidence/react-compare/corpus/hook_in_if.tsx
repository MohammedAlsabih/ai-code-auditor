// EXPECT-ESLINT: rules-of-hooks ERROR (hook called conditionally in if)
import { useState } from 'react';

export function IfBad({ flag }: { flag: boolean }) {
  if (flag) {
    const [a] = useState(1);
    return <p>{a}</p>;
  }
  return null;
}
