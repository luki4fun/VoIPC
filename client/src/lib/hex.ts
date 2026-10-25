// Account ids and relay ids travel as lowercase hex between the backends and
// the front end (voipc_protocol::conv `hex` on the Rust side).

/** Bytes as lowercase hex. */
export function toHex(bytes: ArrayLike<number>): string {
  return Array.from(bytes, (x) => x.toString(16).padStart(2, "0")).join("");
}
