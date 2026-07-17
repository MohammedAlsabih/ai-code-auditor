// EXPECT-ESLINT: rules-of-hooks ERROR (hook inside an event-handler callback)
import { useState } from 'react';

export function Btn() {
  return (
    <button
      onClick={() => {
        const [c] = useState(0);
        console.log(c);
      }}
    >
      x
    </button>
  );
}
