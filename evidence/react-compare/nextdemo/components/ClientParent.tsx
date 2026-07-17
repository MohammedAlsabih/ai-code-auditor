'use client';

import { useState } from 'react';
import { Leaf } from './Leaf';

export function ClientParent() {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button onClick={() => setOpen(!open)}>toggle</button>
      {open ? <Leaf /> : null}
    </div>
  );
}
