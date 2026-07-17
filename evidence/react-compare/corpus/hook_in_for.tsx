// EXPECT-ESLINT: rules-of-hooks ERROR (hook called in a loop)
import { useState } from 'react';

export function ForBad({ items }: { items: string[] }) {
  const out: string[] = [];
  for (let i = 0; i < items.length; i++) {
    const [v] = useState(items[i]);
    out.push(v);
  }
  return <p>{out.join(',')}</p>;
}
