<script lang="ts">
  // The admin panel's Server tab (1.9): what this server calls itself. It stands
  // beside the address everywhere and never replaces it, so it cannot pass for
  // another server. Its look is AdminDialogs.svelte's.

  import { filePick } from "../actions/file-pick.js";
  import { get } from "svelte/store";
  import { makeProfilePicture } from "../image-prep.js";
  import { adminError, adminOp } from "../stores/admin-ui.js";
  import { addNotification } from "../stores/notifications.js";
  import { pictureKey, pictures, serverProfile } from "../stores/profiles.js";
  import { serverAddress } from "../stores/scoped.js";

  let name = $state(get(serverProfile)?.name ?? "");
  let description = $state(get(serverProfile)?.description ?? "");
  const iconUrl = $derived(
    $serverProfile?.icon ? ($pictures.get(pictureKey($serverAddress, $serverProfile.icon)) ?? null) : null,
  );

  async function pick(input: HTMLInputElement) {
    const file = input.files?.[0];
    input.value = "";
    if (!file) return;
    try {
      const image = await makeProfilePicture(new Uint8Array(await file.arrayBuffer()));
      void adminOp({ ServerIconSet: { image: [...image] } });
    } catch (e) {
      adminError.of(get(serverAddress)).set(e instanceof Error ? e.message : String(e));
      addNotification("Could not use that picture", "warning");
    }
  }
</script>

<section class="section">
  <div class="section-title">What this server calls itself</div>
  <p class="admin-hint">People see it above the address, which stays what identifies the server.</p>
  <form class="server-form" onsubmit={(e) => { e.preventDefault(); void adminOp({ ServerProfileSet: { name, description } }); }}>
    <label class="field">
      Name
      <input class="admin-input" aria-label="Server name" bind:value={name} maxlength="32" />
    </label>
    <label class="field">
      Description
      <textarea class="admin-input" aria-label="Server description" bind:value={description} maxlength="256" rows="3"></textarea>
    </label>
    <div class="form-actions">
      <button type="submit" class="btn btn-primary">Save</button>
    </div>
  </form>
</section>

<section class="section">
  <div class="section-title">Icon</div>
  <div class="icon-row">
    {#if iconUrl}<img class="icon" src={iconUrl} alt="The server's icon" />{/if}
    <label class="btn btn-secondary" use:filePick>
      Choose…
      <input type="file" accept="image/*" hidden onchange={(e) => pick(e.currentTarget)} />
    </label>
    {#if $serverProfile?.icon}
      <button type="button" class="btn btn-ghost" onclick={() => adminOp({ ServerIconSet: { image: null } })}>Remove</button>
    {/if}
  </div>
</section>

<style>
  .server-form {
    display: flex;
    flex-direction: column;
    gap: var(--sp-3, 12px);
  }

  .icon-row {
    display: flex;
    align-items: center;
    gap: var(--sp-2, 8px);
  }

  .icon {
    width: 48px;
    height: 48px;
    border-radius: 16px;
    object-fit: cover;
  }
</style>
