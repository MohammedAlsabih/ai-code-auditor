// EXPECT-ESLINT: clean (api.useState is NOT a React hook — member call on a
// non-React object; eslint-plugin-react-hooks only treats React.useX and bare
// useX as hooks). Auditor must AGREE (no R001).
export function ServiceObj({ flag }: { flag: boolean }) {
  if (flag) {
    api.useState(0);
    client.useState(1);
  }
  return null;
}
