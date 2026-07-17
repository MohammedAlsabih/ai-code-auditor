// EXPECT-ESLINT: rules-of-hooks ERROR (hook inside useMemo callback)
import { useMemo, useState } from 'react';

export function MemoNest() {
  const v = useMemo(() => {
    const [x] = useState(1);
    return x;
  }, []);
  return <p>{v}</p>;
}
