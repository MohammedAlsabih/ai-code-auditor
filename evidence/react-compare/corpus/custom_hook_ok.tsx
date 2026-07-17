// EXPECT-ESLINT: CLEAN (custom useXxx hook may call hooks)
import { useState } from 'react';

export function useThing() {
  const [d] = useState<string | null>(null);
  return d;
}
