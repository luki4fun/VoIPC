<script lang="ts">
  import { dialog } from "../actions/dialog.js";
  // "Which of these do you want?", once.
  //
  // Shown on the first connection, right after the audio setup and for the same
  // reason: they are connected and in no voice channel yet, and it is the moment
  // people expect to be asked things. After it, because bad audio is what breaks
  // a call and a layout somebody would rather not have is not.
  //
  // Skipping writes nothing — the same rule the audio setup keeps, so the offer
  // stands next time rather than being marked answered by silence. It also
  // leaves the app where it is, which for anybody who has never picked a layout
  // is the default: there is nothing stored to distinguish them from a fresh
  // install, so they arrive in the modern one and this dialog is how they find
  // the other.

  import { get } from "svelte/store";

  import { LAYOUT_PICKER_VERSION, type LayoutId } from "../ui-prefs.js";
  import { uiPrefs, updateUiPrefs } from "../stores/ui-prefs.js";
  import LayoutPreview from "./LayoutPreview.svelte";

  interface Props {
    onclose: () => void;
  }
  let { onclose }: Props = $props();

  // Whatever is on screen behind the dialog, so the cards agree with the app:
  // the default for a new install, and their own layout for anybody who has one.
  let picked = $state<LayoutId>(get(uiPrefs).layout);

  function confirm() {
    updateUiPrefs((p) => {
      p.layout = picked;
      p.layout_asked_version = LAYOUT_PICKER_VERSION;
    });
    onclose();
  }
</script>

<div class="overlay">
  <div class="layout-setup" aria-label="Choose a layout" use:dialog>
    <h3>How should VoIPC look?</h3>
    <p class="intro">
      Three layouts, the same app underneath. Pick whichever feels familiar — you can change
      it any time in Settings → Appearance.
    </p>

    <div class="choices" role="radiogroup" aria-label="Layout">
      <LayoutPreview layout="modern" selected={picked === "modern"} onpick={() => (picked = "modern")} />
      <LayoutPreview layout="classic" selected={picked === "classic"} onpick={() => (picked = "classic")} />
      <LayoutPreview layout="stage" selected={picked === "stage"} onpick={() => (picked = "stage")} />
    </div>

    <div class="actions">
      <button class="text-link skip-link" onclick={onclose}>Decide later</button>
      <button class="submit-btn btn btn-primary" onclick={confirm}>Use this layout</button>
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    z-index: var(--z-setup);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px;
    background: var(--scrim);
  }

  .layout-setup {
    width: min(620px, 96vw);
    max-height: 90vh;
    overflow-y: auto;
    padding: 24px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 10px;
    box-shadow: var(--shadow-dialog);
  }

  h3 {
    margin-bottom: 6px;
    font-size: var(--fs-xl);
    color: var(--text-primary);
  }

  .intro {
    margin-bottom: 16px;
    font-size: var(--fs-body);
    line-height: 1.5;
    color: var(--text-secondary);
  }

  .choices {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
  }

  .actions {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-top: 20px;
  }

  .skip-link {
    background: transparent;
    color: var(--text-secondary);
    padding: 8px 0;
    font-size: var(--fs-body);
    text-decoration: underline;
  }

  .skip-link:hover {
    color: var(--text-primary);
  }

  .submit-btn {
    padding: 10px 20px;
    font-size: var(--fs-md);
  }
</style>
