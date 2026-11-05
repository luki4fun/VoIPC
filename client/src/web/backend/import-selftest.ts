// The importer's commands in a test build's page (`VOIPC_SELFTEST=1 npm run web`, then
// `/?wizard`), so that the wizard's own screens get clicked with a real mouse. They answer
// from the fixture's dry-run and ask no one: the real ones are client/src-tauri/src/import.rs,
// and crates/voipc-import's tests hold `plan.json` to what the code says. Nothing but a test
// build's `commands.ts` loads this file.
//
// The frames are not played here: `import_replay` is what takes a run to a relay in a lane.
// `import_run` does end the run it was given with a real `ImportEnd`, so the dashboard has
// something true to show.

import plan from "../../../../testkit/6-mock-discord/plan.json";
import { NO_TOKEN } from "../../lib/move-rules";
import type { Session } from "./session";

type Args = Record<string, unknown>;

const GUILD = plan.guild;

/** A run in play, per server: what Stop stops. */
const going = new Map<string, ReturnType<typeof setTimeout>>();

const PHASES = ["roles", "channels", "members", "bans", "emotes", "threads", "messages", "ending"];

function end(session: Session, server: string, run: number, stopped: string | null): void {
  going.delete(server);
  session.sendControl({
    Account: { Admin: { op: { ImportEnd: { run, report: JSON.stringify({ counts: { channels: plan.channels.length }, notes: [] }) } }, code: null } },
  });
  session.emit("import-ended", {
    run,
    stopped,
    // As an end screen's can: a repeated line must not stop the list drawing it
    notes: [...plan.report_preview.slice(0, 4), ...plan.report_preview.slice(0, 1)],
  });
}

const opening = () => ({
  bot_name: "Fixture Bot",
  app_id: "1190000000000000900",
  member_intent: true,
  content_intent: true,
  guilds: [
    { id: GUILD.id, name: GUILD.name, admin: true },
    // Two servers of one name are two servers
    { id: "1190000000000000002", name: GUILD.name, admin: false },
  ],
  invite: "https://discord.com/oauth2/authorize?client_id=1190000000000000900&scope=bot&permissions=8",
});

/** A lane holds a token check back, as Discord can, with a token that starts `held-`, and
 *  answers it later: `__heldOpen[token].yes()` or `.no(words)`. */
function heldOpen(token: string): Promise<unknown> {
  const g = globalThis as unknown as { __heldOpen?: Record<string, { yes: () => void; no: (words: string) => void }> };
  return new Promise((yes, no) => {
    (g.__heldOpen ??= {})[token] = { yes: () => yes(opening()), no };
  });
}

export function answer(cmd: string, args: Args, session: Session): unknown {
  const server = String(args.server);
  // A lane says the hour has passed: the real hub has let go of the token and its dry-run
  if ((cmd === "import_plan" || cmd === "import_run") && (globalThis as unknown as { __tokenGone?: boolean }).__tokenGone) throw NO_TOKEN;
  switch (cmd) {
    case "import_open":
      if (String(args.token).startsWith("held-")) return heldOpen(String(args.token));
      if (args.token !== "fixture-token") throw "the token no longer works";
      return opening();
    case "import_plan":
      return structuredClone(plan);
    case "import_run": {
      const choices = args.choices as { options: { messages: boolean; acknowledged: boolean } };
      if (choices.options.messages && !choices.options.acknowledged) throw "Tick what copying messages means first.";
      const run = Number(args.run);
      let step = 0;
      const tick = () => {
        // As the driver's next frame finds it: `need` no longer reaches this session for a Stop
        if (session.isEnded) {
          going.delete(server);
          session.emit("import-ended", { run, stopped: "The connection to the server was lost. Nothing is lost: run it again to go on from here.", notes: [] });
          return;
        }
        if (step >= PHASES.length) {
          end(session, server, run, null);
          return;
        }
        session.emit("import-progress", { phase: PHASES[step], done: step + 1, total: PHASES.length, channel: step === 6 ? "lounge" : "", waiting: step === 5 ? "Discord asked to wait 2 minutes." : null });
        step++;
        going.set(server, setTimeout(tick, 500));
      };
      tick();
      return null;
    }
    case "import_stop": {
      const t = going.get(server);
      if (t !== undefined) clearTimeout(t);
      going.delete(server);
      session.emit("import-ended", { run: 0, stopped: "You stopped it.", notes: [] });
      return null;
    }
    case "import_forget":
      return null;
    case "import_move_post":
      // What a lane reads back: the one write, and only on this press
      (globalThis as unknown as { __movePosts?: unknown[] }).__movePosts ??= [];
      (globalThis as unknown as { __movePosts: unknown[] }).__movePosts.push({ channel: args.channel, text: args.text, everyone: args.everyone });
      return null;
    default:
      throw `unknown command: ${cmd}`;
  }
}
