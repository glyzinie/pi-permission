import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/**
 * pi-permission entry point.
 *
 * Keep this entry point minimal for now so unfinished helper modules do not
 * prevent Pi from starting.
 */
export default function piPermission(_pi: ExtensionAPI): void {
  // Intentionally minimal.
}
