// EXPECT-ESLINT: CLEAN (exhaustive-deps intentionally ignores effects with NO deps argument)
import { useEffect } from 'react';

export function Title() {
  useEffect(() => {
    document.title = 'x';
  });
  return null;
}
