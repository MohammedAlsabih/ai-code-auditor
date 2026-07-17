// EXPECT-ESLINT: rules-of-hooks ERROR (hook inside try/catch)
import { useState } from 'react';

export function TryBad() {
  try {
    const [v] = useState(0);
    return <p>{v}</p>;
  } catch {
    return null;
  }
}
