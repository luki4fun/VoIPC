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
  };

  // A shadow is a CSS shadow, not a colour: `<input type="color">` cannot edit
  // one, and pretending otherwise would quietly replace it with a hex.
  const COLOUR_TOKENS = TOKENS.filter((t) => !t.startsWith("--shadow"));

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

<button class="disclosure" onclick={() => (showColours = !showColours)}>
  {showColours ? "▾" : "▸"} Custom colours
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
    font-size: 12px;
  }

  .swatch.active {
    border-color: var(--accent);
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
    font-size: 11px;
  }

  .disclosure {
    align-self: flex-start;
    margin-top: 10px;
    padding: 4px 0;
    background: transparent;
    color: var(--text-secondary);
    font-size: 12px;
  }

  .disclosure:hover {
    color: var(--text-primary);
  }

  .count {
    margin-left: 6px;
    color: var(--accent);
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
    font-size: 12px;
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
    font-size: 11px;
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
    font-size: 12px;
    background: var(--bg-tertiary);
    color: var(--text-secondary);
  }

  .reset-colours:hover {
    color: var(--text-primary);
  }
</style>
