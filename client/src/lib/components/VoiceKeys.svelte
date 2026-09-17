<script lang="ts">
  // Everything that opens the microphone without anybody clicking: the
  // push-to-talk key, Ctrl+M and Ctrl+D, the tray menu, the OS-wide hotkeys,
  // and the polling that voice activation needs to decide when you are talking.
  //
  // No markup. It lives in App.svelte, *outside* whichever layout is on screen,
  // and that placement is the whole point: switching layout destroys and rebuilds
  // the shell, so a user who changes it mid-call would otherwise either lose
  // push-to-talk or end up with two keydown handlers racing start_transmit
  // against stop_transmit. This was part of VoiceControls until the second
  // layout, which has no voice bar to hang it on.

  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, onDestroy } from "svelte";

  import { connectionState, isTransmitting, userId } from "../stores/connection.js";
  import { currentChannelId } from "../stores/channels.js";
  import { speakingUsers } from "../stores/users.js";
  import { audioSetupOpen, pttKey, pttHoldMode } from "../stores/settings.js";
  import {
    audioLevel,
    startTransmit,
    stopTransmit,
    toggleDeafen,
    toggleMute,
    vadThreshold,
    voiceMode,
  } from "../stores/voice.js";

  // Voice is disabled in the General lobby (channel 0)
  let voiceDisabled = $derived($currentChannelId === 0);

  // VAD/AlwaysOn: auto-start transmit when connected to a channel.
  //
  // Not while the audio setup is up: it is using the capture device for its
  // own meter, and `start_mic_test` refuses to run while we transmit — so
  // without this guard the wizard's microphone step would be dead exactly
  // for the people who most need it to work.
  $effect(() => {
    if (
      $voiceMode !== "ptt" &&
      !voiceDisabled &&
      $connectionState === "connected" &&
      !$isTransmitting &&
      !$audioSetupOpen
    ) {
      startTransmit();
    }
  });

  // A new connection starts with no capture task; the store must follow,
  // or the auto-start above never re-arms after a reconnect
  $effect(() => {
    if ($connectionState !== "connected") isTransmitting.set(false);
  });

  // Poll audio level when in VAD mode and connected
  let levelPollInterval: ReturnType<typeof setInterval> | null = null;

  $effect(() => {
    if ($voiceMode === "vad" && $connectionState === "connected" && $isTransmitting) {
      if (!levelPollInterval) {
        levelPollInterval = setInterval(() => {
          invoke<number>("get_audio_level").then((level) => {
            audioLevel.set(level);
          }).catch(() => {});
        }, 66); // ~15 Hz
      }
    } else {
      if (levelPollInterval) {
        clearInterval(levelPollInterval);
        levelPollInterval = null;
      }
    }

    return () => {
      if (levelPollInterval) {
        clearInterval(levelPollInterval);
        levelPollInterval = null;
      }
    };
  });

  // Update local user's speaking state in VAD mode based on audio level vs threshold.
  // This makes the local user's indicator in the UserList reflect actual voice activity
  // (the server doesn't relay our own voice packets back to us).
  $effect(() => {
    if ($voiceMode === "vad" && $isTransmitting && $userId > 0) {
      const speaking = $audioLevel >= $vadThreshold;
      speakingUsers.update((set) => {
        const next = new Set(set);
        if (speaking) {
          next.add($userId);
        } else {
          next.delete($userId);
        }
        return next;
      });
    }
  });

  // Parse the PTT binding string (e.g. "Ctrl+Space", "ControlLeft") into parts
  function parsePttBinding(): { needCtrl: boolean; needAlt: boolean; needShift: boolean; keyCode: string } {
    const parts = $pttKey.split("+");
    let needCtrl = false, needAlt = false, needShift = false;
    let keyCode = "";
    for (const part of parts) {
      if (part === "Ctrl") needCtrl = true;
      else if (part === "Alt") needAlt = true;
      else if (part === "Shift") needShift = true;
      else keyCode = part;
    }
    return { needCtrl, needAlt, needShift, keyCode };
  }

  // Check if the full PTT binding matches (all modifiers + trigger key)
  function matchesPttBinding(e: KeyboardEvent): boolean {
    const { needCtrl, needAlt, needShift, keyCode } = parsePttBinding();
    if (needCtrl && !e.ctrlKey) return false;
    if (needAlt && !e.altKey) return false;
    if (needShift && !e.shiftKey) return false;
    return e.code === keyCode;
  }

  // Check if a keyup event should stop PTT.
  // In trigger mode: stop when the trigger key is released.
  // In hold mode with modifiers: stop when a required modifier is released.
  // In hold mode without modifiers: stop when the trigger key is released.
  function shouldStopPtt(e: KeyboardEvent): boolean {
    const { needCtrl, needAlt, needShift, keyCode } = parsePttBinding();
    if ($pttHoldMode && (needCtrl || needAlt || needShift)) {
      // Hold mode with modifiers — stop when any required modifier is released
      if (needCtrl && e.key === "Control") return true;
      if (needAlt && e.key === "Alt") return true;
      if (needShift && e.key === "Shift") return true;
      return false;
    }
    // Trigger mode, or no modifiers — stop when the trigger key is released
    return e.code === keyCode;
  }

  // Window-level keyboard PTT and shortcuts (fallback when app is focused)
  let keydownHandler: ((e: KeyboardEvent) => void) | null = null;
  let keyupHandler: ((e: KeyboardEvent) => void) | null = null;
  let toggleUnlisten: Array<() => void> = [];

  onMount(() => {
    keydownHandler = (e: KeyboardEvent) => {
      // Don't trigger shortcuts when typing in input/textarea
      const target = e.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return;

      // PTT key — only in PTT mode
      if ($voiceMode === "ptt" && matchesPttBinding(e) && !e.repeat) {
        e.preventDefault();
        startTransmit();
        // Whatever else this key is bound to, it is the push-to-talk key
        // first: Ctrl+M below would otherwise mute the microphone that the
        // same press just opened.
        return;
      }

      // Ctrl+M / Meta+M = toggle mute
      if ((e.ctrlKey || e.metaKey) && e.code === "KeyM") {
        e.preventDefault();
        toggleMute();
      }

      // Ctrl+D / Meta+D = toggle deafen
      if ((e.ctrlKey || e.metaKey) && e.code === "KeyD") {
        e.preventDefault();
        toggleDeafen();
      }
    };

    keyupHandler = (e: KeyboardEvent) => {
      // No input/textarea guard here (unlike keydown): releasing the PTT
      // key must always stop the mic, even if focus moved into the chat
      // box while it was held. The path is gated on $isTransmitting.

      // Stop transmit when the released key breaks the PTT binding
      if ($voiceMode === "ptt" && $isTransmitting && shouldStopPtt(e)) {
        e.preventDefault();
        stopTransmit();
      }
    };

    window.addEventListener("keydown", keydownHandler);
    window.addEventListener("keyup", keyupHandler);

    // Tray menu and global hotkeys request toggles via these events —
    // routed through the same functions so UI + server stay in sync
    listen("toggle-mute-request", () => toggleMute()).then((fn) =>
      toggleUnlisten.push(fn),
    );
    listen("toggle-deafen-request", () => toggleDeafen()).then((fn) =>
      toggleUnlisten.push(fn),
    );
  });

  onDestroy(() => {
    if (keydownHandler) window.removeEventListener("keydown", keydownHandler);
    if (keyupHandler) window.removeEventListener("keyup", keyupHandler);
    toggleUnlisten.forEach((fn) => fn());
  });
</script>
