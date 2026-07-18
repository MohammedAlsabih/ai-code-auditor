// EXPECT-ESLINT: rules-of-hooks ERROR (React.useState called conditionally)
import * as React from 'react';

export function NsHook({ flag }: { flag: boolean }) {
  if (flag) {
    const [v] = React.useState(0);
    return <p>{v}</p>;
  }
  return null;
}
