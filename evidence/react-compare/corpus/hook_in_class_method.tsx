// EXPECT-ESLINT: rules-of-hooks ERROR (hook in class component method)
import * as React from 'react';
import { useState } from 'react';

export class Legacy extends React.Component {
  render() {
    const [v] = useState(0);
    return <p>{v}</p>;
  }
}
