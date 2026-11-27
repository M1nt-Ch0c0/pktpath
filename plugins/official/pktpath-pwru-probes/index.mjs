// Official PktPath pwru-class kernel probes plugin (ABI v1).
// Kernel-side probes are delivered via kernel_probes in manifest.json.
export default {
  id: "pktpath.pwru-probes",
  name: "PktPath Official Full-Path & pwru Kernel Probes",
  activate() {
    return { ok: true };
  },
};
