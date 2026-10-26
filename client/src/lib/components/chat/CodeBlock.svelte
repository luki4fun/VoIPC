<script lang="ts">
  import type { CodeSeg } from "../../highlight.js";

  // A fenced block: the code exactly as sent, in the code face, coloured
  // where this build knows the language. The grammars load on first use.
  let { lang, code }: { lang: string; code: string } = $props();

  let segs = $state<CodeSeg[] | null>(null);
  $effect(() => {
    const [l, c] = [lang, code];
    segs = null;
    if (!l) return;
    let live = true;
    import("../../highlight.js").then(
      (m) => {
        if (live) segs = m.highlight(l, c);
      },
      () => {},
    );
    return () => {
      live = false;
    };
  });

  let codeEl = $state<HTMLElement | null>(null);
  let copyState = $state<"idle" | "copied" | "select">("idle");
  let resetTimer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      copyState = "copied";
    } catch {
      // No clipboard here (an insecure origin, a WebView that says no): the
      // code is selected instead, for the reader's own Ctrl+C
      if (codeEl) {
        const range = document.createRange();
        range.selectNodeContents(codeEl);
        const sel = getSelection();
        sel?.removeAllRanges();
        sel?.addRange(range);
      }
      copyState = "select";
    }
    clearTimeout(resetTimer);
    resetTimer = setTimeout(() => (copyState = "idle"), 2500);
  }
</script>

{#snippet run(list: CodeSeg[])}{#each list as s}{#if "v" in s}{s.v}{:else}<span class="tok-{s.k}">{@render run(s.c)}</span>{/if}{/each}{/snippet}

<div class="code-block">
  <pre><code bind:this={codeEl}>{#if segs}{@render run(segs)}{:else}{code}{/if}</code></pre>
  <button class="btn btn-ghost copy" type="button" onclick={copy} aria-live="polite">
    {copyState === "copied" ? "Copied" : copyState === "select" ? "Selected — press Ctrl+C" : "Copy"}
  </button>
</div>

<style>
  .code-block {
    position: relative;
    margin: 4px 0;
  }

  pre {
    margin: 0;
    padding: 8px 12px;
    /* Room for the copy button on the first line */
    padding-right: 72px;
    overflow-x: auto;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
    font-size: 0.92em;
    line-height: 1.45;
    /* Code keeps its lines: it scrolls, it never wraps */
    white-space: pre;
  }

  code {
    font: inherit;
  }

  .copy {
    position: absolute;
    top: 2px;
    right: 2px;
    min-height: var(--hit);
    padding: 4px 10px;
    font-size: var(--fs-sm);
    font-weight: 500;
  }

  .tok-keyword {
    color: var(--code-keyword);
  }
  .tok-string {
    color: var(--code-string);
  }
  .tok-comment {
    color: var(--code-comment);
    font-style: italic;
  }
  .tok-number {
    color: var(--code-number);
  }
  .tok-fn {
    color: var(--code-fn);
  }
</style>
