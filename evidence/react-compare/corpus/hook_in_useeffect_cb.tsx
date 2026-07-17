// EXPECT-ESLINT: rules-of-hooks ERROR (hook inside useEffect callback)
import { useEffect, useState } from 'react';

export function EffectNest() {
  useEffect(() => {
    const [x] = useState(0);
    console.log(x);
  }, []);
  return null;
}
