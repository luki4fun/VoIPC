// `PostsMark`s as the browser's decoder gives them, and as the desktop's event has
// them: `u64`s are bigints there and `None` undefined.

interface DecodedMark {
  account?: number[] | null;
  name: string;
  since_ms: bigint | number;
  before_ms: bigint | number;
  by: string;
}

export function postsMarks(marks: readonly DecodedMark[]) {
  return marks.map((m) => ({
    account: m.account ?? null,
    name: m.name,
    since_ms: Number(m.since_ms),
    before_ms: Number(m.before_ms),
    by: m.by,
  }));
}
