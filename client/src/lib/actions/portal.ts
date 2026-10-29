// Out from under the component that draws it, to the end of <body>.
//
// A `position: fixed` box is placed against the window only while no ancestor
// says otherwise, and a container-query box does (`container-type` implies
// layout containment, as a transform does): a menu opened at the pointer then
// lands wherever that ancestor happens to start. Moving it to <body> puts it
// back where the pointer was.

export function portal(node: HTMLElement) {
  document.body.appendChild(node);
  return {
    destroy() {
      node.remove();
    },
  };
}
