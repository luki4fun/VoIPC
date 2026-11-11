// The one way the browser opens a page a relay named for a sign-in (W3-10).
//
// `provider_page_ok` was tested as a function, and the command that must call it was not:
// without the call every test stayed green and a hostile relay opened any page it named.
// The command goes through here, and this is what the test holds.

export const NOT_A_PROVIDERS_PAGE = "This server named a page that is no provider's: not opening it.";

/** Opens `page` if `ok` says it is a provider's own. Throws the refusal as the backend's
 *  commands do, a string, and opens nothing. */
export function openProviderPage(page: string, ok: (url: string) => boolean, open: (url: string) => void): void {
  if (!ok(page)) throw NOT_A_PROVIDERS_PAGE;
  open(page);
}
