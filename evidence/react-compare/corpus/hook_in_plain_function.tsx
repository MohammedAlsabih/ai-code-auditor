// EXPECT-ESLINT: rules-of-hooks ERROR (hook in plain lowercase function)
import { useState } from 'react';

export function loadData() {
  const [d] = useState<string | null>(null);
  return d;
}
