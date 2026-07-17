// EXPECT-ESLINT: CLEAN (hook at top level of arrow component assigned to Capitalized const)
import { useState } from 'react';

export const Card = () => {
  const [n] = useState(0);
  return <div>{n}</div>;
};
