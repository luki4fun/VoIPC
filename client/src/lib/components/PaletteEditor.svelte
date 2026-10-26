<script lang="ts">
  // Pick a palette, then change any colour in it.
  //
  // Lives outside SettingsPanel because that file is already 1300 lines, and
  // because the swatches and the colour grid are one self-contained thing.
  //
  // Everything previews live: the store writes straight to the document's
  // custom properties, so there is no Apply button and nothing to undo but the
  // reset. That is the whole reason the app was built on tokens.

  import { PALETTES, TOKENS, paletteById, type TokenName } from "../theme.js";
  import { uiPrefs, updateUiPrefs } from "../stores/ui-prefs.js";
  import Icon from "./Icons.svelte";

  /** The plain-English name of each token, for people who are not us. */
  const LABELS: Record<TokenName, string> = {
    "--bg-primary": "Background",
    "--bg-secondary": "Sidebars and bars",
    "--bg-tertiary": "Inputs and buttons",
    "--bg-hover": "Hover",
    "--text-primary": "Text",
    "--text-secondary": "Secondary text",
    "--accent": "Accent",
    "--accent-hover": "Accent (hover)",
    "--success": "Success",
    "--danger": "Danger",
    "--warning": "Warning",
    "--border": "Borders",
    "--speaking": "Speaking",
    "--well": "Recessed areas",
    "--scrollbar": "Scrollbar",
    "--shadow-menu": "Menu shadow",
    "--shadow-dialog": "Dialog shadow",
    "--on-accent": "Text on accent",
    "--on-danger": "Text on danger",
    "--on-success": "Text on success",
    "--on-warning": "Text on warning",
    "--text-muted": "Dimmed text",
    "--scrim": "Behind dialogs",
    "--focus-ring": "Keyboard focus",
    "--code-keyword": "Code: keywords",
    "--code-string": "Code: strings",
    "--code-comment": "Code: comments",
    "--code-number": "Code: numbers",
    "--code-fn": "Code: names",
  };

  // A shadow is a CSS shadow, not a colour: `<input type="color">` cannot edit
  // one, and pretending otherwise would quietly replace it with a hex. The
  // scrim is a translucent black for the same reason.
  const COLOUR_TOKENS = TOKENS.filter((t) => !t.startsWith("--shadow") && t !== "--scrim");

  let showColours = $state(false);

  const palette = $derived(paletteById($uiPrefs.palette));
  const overrides = $derived($uiPrefs.palette_overrides);
  const overriddenCount = $derived(Object.keys(overrides).length);

  function valueOf(token: TokenName): string {
    return overrides[token] ?? palette.tokens[token];
  }

  function choose(id: string) {
    updateUiPrefs((p) => {
      p.palette = id;
      p.palette_chosen = true;
    });
  }

  function setColour(token: TokenName, value: string) {
    updateUiPrefs((p) => {
      p.palette_overrides[token] = value;
    });
  }

  function clearColour(token: TokenName) {
    updateUiPrefs((p) => {
      delete p.palette_overrides[token];
    });
  }

  function clearAll() {
    updateUiPrefs((p) => {
      p.palette_overrides = {};
    });
  }

  /** `rgba(...)` cannot go in a colour input; show it as opaque for editing. */
  function asHex(value: string): string {
    return value.startsWith("#") ? value : "#000000";
  }
</script>

<div class="swatches">
  {#each PALETTES as p (p.id)}
    <button
      class="swatch"
      class:active={$uiPrefs.palette === p.id}
      data-palette={p.id}
      aria-pressed={$uiPrefs.palette === p.id}
      onclick={() => choose(p.id)}
      title={p.label}
    >
      <span class="chips">
        <span style="background: {p.tokens['--bg-primary']}"></span>
        <span style="background: {p.tokens['--bg-secondary']}"></span>
        <span style="background: {p.tokens['--accent']}"></span>
      </span>
      <span class="swatch-label">{p.label}</span>
    </button>
  {/each}
</div>

<button class="disclosure" aria-expanded={showColours} onclick={() => (showColours = !showColours)}>
  <span class="chevron" class:open={showColours} aria-hidden="true"><Icon name="chevron-down" size={14} /></span>
  Custom colours
  {#if overriddenCount > 0}<span class="count">{overriddenCount} changed</span>{/if}
</button>

{#if showColours}
  <div class="colours">
    {#each COLOUR_TOKENS as token (token)}
      <label class="colour-row">
        <input
          type="color"
          value={asHex(valueOf(token))}
          oninput={(e) => setColour(token, (e.target as HTMLInputElement).value)}
        />
        <span class="colour-name">{LABELS[token]}</span>
        {#if overrides[token]}
          <button class="revert" onclick={() => clearColour(token)} title="Back to the palette's colour"
            >Revert</button
          >
        {/if}
      </label>
    {/each}
  </div>
  {#if overriddenCount > 0}
    <button class="reset-colours" onclick={clearAll}>Reset all colours</button>
  {/if}
{/if}

<style>
  .swatches {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .swatch {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
    padding: 8px;
    background: var(--bg-tertiary);
    border: 2px solid transparent;
    border-radius: 8px;
    color: var(--text-secondary);
    font-size: var(--fs-sm);
  }

  .swatch.active {
    border-color: var(--text-primary);
    color: var(--text-primary);
  }

  .chips {
    display: flex;
    border-radius: 4px;
    overflow: hidden;
    border: 1px solid var(--border);
  }

  .chips > span {
    width: 20px;
    height: 20px;
  }

  .swatch-label {
    font-size: var(--fs-micro);
  }

  .disclosure {
    align-self: flex-start;
    margin-top: 10px;
    padding: 4px 0;
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--fs-sm);
  }

  .disclosure:hover {
    color: var(--text-primary);
  }

  .count {
    margin-left: 6px;
    color: var(--text-secondary);
  }

  .colours {
    display: grid;
    grid-template-columns: 1fr;
    gap: 4px;
    margin-top: 6px;
  }

  .colour-row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--fs-sm);
    color: var(--text-secondary);
  }

  .colour-row input[type="color"] {
    width: 32px;
    height: 24px;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: transparent;
    cursor: pointer;
  }

  .colour-name {
    flex: 1;
  }

  .revert {
    padding: 2px 8px;
    font-size: var(--fs-micro);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }

  .revert:hover {
    color: var(--text-primary);
  }

  .reset-colours {
    align-self: flex-start;
    margin-top: 8px;
    padding: 6px 12px;
    font-size: var(--fs-sm);
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }

  .reset-colours:hover {
    color: var(--text-primary);
  }

  .chevron {
    display: inline-flex;
    transform: rotate(-90deg);
    transition: transform var(--dur-fast);
  }

  .chevron.open {
    transform: none;
  }
</style>
