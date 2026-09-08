// Deterministic avatar colour from a username, shared by the channel list,
// the direct-message list and the virtual room.

const AVATAR_COLORS = [
  "#5865F2", "#57F287", "#FEE75C", "#EB459E",
  "#ED4245", "#3498db", "#e67e22", "#1abc9c",
];

export function avatarColor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
}
