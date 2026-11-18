<script lang="ts">
  // The admin panel's Load tab (1.14): what this relay carries now, asked every two seconds
  // while the tab is open. Warnings first, in the relay's own words: it knows its limits.
  // Its media edges (1.15, `[pool]`) get a table of their own, only when it has any.

  import { invoke } from "@tauri-apps/api/core";
  import { adminLoad } from "../stores/load.js";
  import { serverAddress } from "../stores/scoped.js";

  $effect(() => {
    const server = $serverAddress;
    const ask = () => invoke("admin_load", { server }).catch(() => {});
    ask();
    const every = setInterval(ask, 2000);
    return () => clearInterval(every);
  });

  const r = $derived($adminLoad);
  // A relay at 25 has no edges to say anything of
  const edges = $derived(r?.edges ?? []);
  const mbit = (kbps: number) => (kbps / 1000).toFixed(kbps < 10_000 ? 1 : 0);
</script>

{#if !r}
  <p class="admin-hint">Asking the server…</p>
{:else}
  {#if r.warnings.length > 0}
    <section class="section">
      <div class="section-title">Needs a look</div>
      <ul class="list warnings">
        {#each r.warnings as w (w)}
          <li>{w}</li>
        {/each}
      </ul>
    </section>
  {/if}

  <section class="section">
    <div class="section-title">People</div>
    <ul class="list">
      <li>{r.online} online of {r.max_users} (<code>max_users</code>)</li>
      <li>{r.lobby} in General, {r.in_rooms} in rooms and channels</li>
      <li>
        General's list is live up to {r.live_lobby} (<code>live_lobby</code>){r.lobby > r.live_lobby
          ? ": past that now, so it comes in pages"
          : ""}
      </li>
    </ul>
  </section>

  <section class="section">
    <div class="section-title">Screen shares</div>
    <p class="admin-hint">
      Video sent: {mbit(r.video_kbps)} of {mbit(r.video_budget_kbps)} Mbit/s (<code>[media] video_egress_mbit</code>),
      counted at what each share's resolution may send{edges.length > 0 ? ", one copy per edge that carries a share" : ""}.
    </p>
    {#if r.shares.length === 0}
      <p class="admin-hint">Nobody is sharing.</p>
    {:else}
      <ul class="list">
        {#each r.shares as s (s.channel_id + ":" + s.sharer)}
          {#if edges.length > 0}
            <li>
              {s.sharer}: {s.viewers} watching, {s.viewers - s.on_edges} of {s.cap} on this relay and {s.on_edges} on
              edges, up to {mbit(s.kbps)} Mbit/s each
            </li>
          {:else}
            <li>{s.sharer}: {s.viewers} of {s.cap} viewers, up to {mbit(s.kbps)} Mbit/s each</li>
          {/if}
        {/each}
      </ul>
    {/if}
  </section>

  {#if edges.length > 0}
    <section class="section">
      <div class="section-title">Edges</div>
      <p class="admin-hint">
        The media edges of <code>[pool]</code>. Viewers and Mbit/s are what this relay gave each edge, against the
        edge's own limits; sent, processor and memory are what the edge last reported.
      </p>
      <div class="table-wrap">
        <table class="edges">
          <thead>
            <tr>
              <th scope="col">Edge</th>
              <th scope="col">Linked</th>
              <th scope="col">Viewers</th>
              <th scope="col">Shares</th>
              <th scope="col">Mbit/s</th>
              <th scope="col">Processor</th>
              <th scope="col">Report</th>
            </tr>
          </thead>
          <tbody>
            {#each edges as e (e.name)}
              <tr>
                <td>
                  <span class="edge-name">{e.name}</span>
                  <span class="sub">{e.address}</span>
                </td>
                <td>
                  {#if e.online}
                    <span class="online">online</span>
                  {:else}
                    <span class="offline">offline</span>
                  {/if}
                  {#if e.pool_version > 0}<span class="sub">pool v{e.pool_version}</span>{/if}
                </td>
                <td>{e.viewers} / {e.max_viewers}</td>
                <td>{e.shares} / {e.max_shares}</td>
                <td>
                  {mbit(e.kbps)} given of {mbit(e.budget_kbps)}
                  {#if e.online}<span class="sub">{mbit(e.egress_kbps)} sent</span>{/if}
                </td>
                {#if e.online}
                  <td>
                    {e.cpu_secs} s
                    <span class="sub">{e.rss_mib} MiB</span>
                  </td>
                  <td>
                    {e.report_age_secs} s ago
                    {#if e.frames_dropped > 0}<span class="sub">{e.frames_dropped} frames dropped</span>{/if}
                  </td>
                {:else}
                  <td class="none">—</td>
                  <td class="none">—</td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  <section class="section">
    <div class="section-title">The relay</div>
    <ul class="list">
      <li>{r.rss_mib} MiB of memory, {r.cpu_secs} s of processor since it started</li>
      <li>{r.udp_dropped} UDP datagrams dropped for a full buffer since it started</li>
      {#each r.last_minute as line (line)}
        <li>Last minute — {line}</li>
      {/each}
    </ul>
  </section>
{/if}

<style>
  .warnings li {
    color: var(--warning, var(--text-primary));
  }

  /* Wider than a phone: the table scrolls in its own box, never the panel */
  .table-wrap {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: var(--r-md, 6px);
  }

  .edges {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--fs-sm);
    font-variant-numeric: tabular-nums;
  }

  .edges th,
  .edges td {
    padding: 6px var(--sp-3, 12px);
    text-align: left;
    vertical-align: top;
    white-space: nowrap;
  }

  .edges th {
    font-weight: 600;
    color: var(--text-secondary);
  }

  .edges td {
    border-top: 1px solid var(--border);
    color: var(--text-primary);
  }

  .edge-name {
    font-weight: 600;
  }

  .sub {
    display: block;
    color: var(--text-secondary);
  }

  .online {
    color: var(--success, var(--text-primary));
  }

  .offline {
    color: var(--warning, var(--text-primary));
  }

  .none {
    color: var(--text-muted, var(--text-secondary));
  }
</style>
