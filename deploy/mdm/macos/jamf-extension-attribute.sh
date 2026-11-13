#!/bin/bash
# Jamf Pro extension attribute: "nandi coverage".
#
# Reports how many of the logged-in user's MCP servers go through nandi and
# whether the coding agents have the nandi hook, e.g.
#   3 of 4 MCP servers via nandi; hooks 2 of 2
# Use it in a smart group (e.g. "nandi coverage" does not start with "all")
# to find Macs with agents that bypass nandi.

NANDI=/usr/local/bin/nandi
[ -x "$NANDI" ] || { echo "<result>not installed</result>"; exit 0; }

USER_NAME=$(stat -f %Su /dev/console)
if [ -z "$USER_NAME" ] || [ "$USER_NAME" = "root" ] || [ "$USER_NAME" = "loginwindow" ]; then
  echo "<result>no user logged in</result>"
  exit 0
fi

# Scan as the user: discover reads their home directory.
JSON=$(sudo -u "$USER_NAME" -H "$NANDI" discover --json 2>/dev/null)
RESULT=$(NANDI_JSON="$JSON" /usr/bin/osascript -l JavaScript -e '
  ObjC.import("stdlib");
  let out;
  try {
    const c = JSON.parse($.getenv("NANDI_JSON")).coverage;
    const all = c.servers_total > 0 && c.servers_via_nandi === c.servers_total && c.hooks_installed === c.hook_clients;
    out = (all ? "all: " : "") + c.servers_via_nandi + " of " + c.servers_total + " MCP servers via nandi; hooks " +
      c.hooks_installed + " of " + c.hook_clients;
  } catch (e) {
    out = "scan failed";
  }
  out;
' 2>/dev/null)
echo "<result>${RESULT:-scan failed}</result>"
