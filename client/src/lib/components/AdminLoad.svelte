<script lang="ts">
  // The admin panel's Load tab (1.14): what this relay carries now, asked every two seconds
  // while the tab is open. Warnings first, in the relay's own words: it knows its limits.

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
      counted at what each share's resolution may send.
    </p>
    {#if r.shares.length === 0}
      <p class="admin-hint">Nobody is sharing.</p>
    {:else}
      <ul class="list">
        {#each r.shares as s (s.channel_id + ":" + s.sharer)}
          <li>{s.sharer}: {s.viewers} of {s.cap} viewers, up to {mbit(s.kbps)} Mbit/s each</li>
        {/each}
      </ul>
    {/if}
  </section>

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
</style>
