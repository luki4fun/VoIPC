<script lang="ts">
  // The Stage layout out of a call: every voice channel as a card — who is in
  // it, who is live — and one button to go in. The same channel actions as
  // the sidebars (stores/channel-ui.ts), and the same roster rule: a channel
  // that hides its members or has a password shows only what this client may
  // know (roster-rules.ts rosterForRow).

  import { avatarStyle } from "../../avatar.js";
  import { shortName } from "../../username.js";
  import { isAdmin } from "../../stores/connection.js";
  import { currentChannelId } from "../../stores/channels.js";
  import { channelRosters } from "../../stores/rosters.js";
  import { users } from "../../stores/users.js";
  import { visibleChannels } from "../../stores/roster.js";
  import { voiceMode } from "../../stores/voice.js";
  import { joinChannel } from "../../stores/channel-ui.js";
  import { rosterForRow } from "../../roster-rules.js";
  import Icon from "../Icons.svelte";
  import ChannelTags from "../ChannelTags.svelte";

  const voiceChannels = $derived($visibleChannels.filter((c) => !c.text));

  /** Said before anybody joins: an open microphone is not a surprise to find out about in a call. */
  const MODE_WORDS = { ptt: "push to talk", vad: "voice activation", always_on: "always on" } as const;
</script>

<section class="cards" aria-label="Voice channels">
  <header class="cards-head">
    <h2>Pick a channel to talk in</h2>
    <p>Your microphone opens by <strong>{MODE_WORDS[$voiceMode]}</strong> when you join; change it in Settings → Voice &amp; video.</p>
  </header>

  {#if voiceChannels.length === 0}
    <p class="empty">This server has no voice channels yet. Create one from the channel list.</p>
  {:else}
    <ul class="grid">
      {#each voiceChannels as channel (channel.channel_id)}
        {@const members = rosterForRow(channel, $channelRosters, $currentChannelId, $users, $isAdmin)}
        {@const hidden = channel.hide_members && !$isAdmin}
        {@const live = members.filter((m) => m.is_screen_sharing)}
        <li class="card" data-stage-card={channel.channel_id}>
          <div class="card-top">
            <span class="card-icon" aria-hidden="true"><Icon name="volume" size={18} /></span>
            <span class="card-name">{channel.name}</span>
            {#if channel.has_password}<span class="card-icon" title="Password"><Icon name="lock" size={14} /></span>{/if}
            <ChannelTags {channel} />
          </div>
          {#if channel.description}<p class="card-desc">{channel.description}</p>{/if}

          <div class="card-people">
            {#if hidden}
              <span class="quiet">Members hidden</span>
            {:else if members.length === 0}
              <span class="quiet">Nobody here yet</span>
            {:else}
              <span class="faces" aria-hidden="true">
                {#each members.slice(0, 6) as m (m.user_id)}
                  <span class="face" style={avatarStyle(m.username)} title={shortName(m.username)}
                    >{m.username.charAt(0).toUpperCase()}</span
                  >
                {/each}
              </span>
              <span class="count num">
                {members.length === 1 ? shortName(members[0].username) : `${members.length} people`}
              </span>
            {/if}
            {#if live.length > 0}
              <span class="live-badge"><span class="live-dot" aria-hidden="true"></span>{live.length === 1 ? "1 live" : `${live.length} live`}</span>
            {/if}
          </div>

          <button
            class="btn btn-primary join"
            onclick={() => joinChannel(channel.channel_id, channel.has_password)}
            aria-label="Join {channel.name}"
          >Join</button>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .cards {
    display: flex;
    flex-direction: column;
    gap: var(--sp-4);
    width: 100%;
    max-width: 960px;
    margin: 0 auto;
    padding: var(--sp-6) var(--sp-4);
  }

  .cards-head h2 {
    font-size: var(--fs-xl);
    color: var(--text-primary);
  }

  .cards-head p,
  .empty {
    margin-top: var(--sp-1);
    font-size: var(--fs-body);
    color: var(--text-secondary);
  }

  .grid {
    list-style: none;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: var(--sp-3);
  }

  .card {
    display: flex;
    flex-direction: column;
    gap: var(--sp-2);
    padding: var(--sp-4);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
  }

  .card-top {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    min-width: 0;
  }

  .card-icon {
    display: inline-flex;
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .card-name {
    flex: 1;
    min-width: 0;
    font-size: var(--fs-md);
    font-weight: 600;
    color: var(--text-primary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .card-desc {
    font-size: var(--fs-sm);
    color: var(--text-secondary);
    line-height: 1.4;
  }

  .card-people {
    display: flex;
    align-items: center;
    gap: var(--sp-2);
    min-height: 28px;
    flex-wrap: wrap;
  }

  .faces {
    display: flex;
  }

  .face {
    display: grid;
    place-items: center;
    width: 26px;
    height: 26px;
    margin-right: -6px;
    border-radius: 50%;
    border: 2px solid var(--bg-secondary);
    font-size: var(--fs-micro);
    font-weight: 700;
  }

  .count,
  .quiet {
    margin-left: var(--sp-2);
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .quiet {
    margin-left: 0;
    color: var(--text-muted);
  }

  .live-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-left: auto;
    font-size: var(--fs-sm);
    font-weight: 600;
    color: var(--accent);
  }

  .live-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
  }

  .join {
    align-self: flex-start;
    margin-top: auto;
  }
</style>
