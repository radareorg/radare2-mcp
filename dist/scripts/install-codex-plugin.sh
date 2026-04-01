#!/bin/sh
set -eu

PLUGIN_ID="r2mcp"
SOURCE_DIR="dist/codex-plugin"
PLUGIN_ROOT="plugins/${PLUGIN_ID}"
MARKETPLACE=".agents/plugins/marketplace.json"

rm -rf "${PLUGIN_ROOT}"
mkdir -p "$(dirname "${PLUGIN_ROOT}")"
cp -R "${SOURCE_DIR}" "${PLUGIN_ROOT}"

mkdir -p "$(dirname "${MARKETPLACE}")"

if [ -f "${MARKETPLACE}" ]; then
	perl -MJSON::PP -0pi -e '
		my $plugin = "r2mcp";
		my $entry = {
			name => $plugin,
			source => {
				source => "local",
				path => "./plugins/$plugin",
			},
			policy => {
				installation => "AVAILABLE",
				authentication => "ON_INSTALL",
			},
			category => "Coding",
		};
		my $payload = eval { decode_json($_) };
		die "invalid marketplace json\n" if !$payload || ref($payload) ne "HASH";
		$payload->{name} = "local-repo" if !defined($payload->{name}) || $payload->{name} eq "";
		$payload->{interface} = {} if ref($payload->{interface}) ne "HASH";
		$payload->{interface}{displayName} = "Local Repo Plugins"
			if !defined($payload->{interface}{displayName}) || $payload->{interface}{displayName} eq "";
		$payload->{plugins} = [] if ref($payload->{plugins}) ne "ARRAY";
		my $replaced = 0;
		for my $i (0 .. $#{$payload->{plugins}}) {
			my $item = $payload->{plugins}[$i];
			next if ref($item) ne "HASH";
			next if ($item->{name} // "") ne $plugin;
			$payload->{plugins}[$i] = $entry;
			$replaced = 1;
			last;
		}
		push @{$payload->{plugins}}, $entry if !$replaced;
		$_ = JSON::PP->new->pretty->canonical->encode($payload);
	' "${MARKETPLACE}"
else
	python3 - "${MARKETPLACE}" "${PLUGIN_ID}" <<'PY'
import json
import sys

marketplace_path = sys.argv[1]
plugin_id = sys.argv[2]

payload = {
    "name": "local-repo",
    "interface": {
        "displayName": "Local Repo Plugins",
    },
    "plugins": [
        {
            "name": plugin_id,
            "source": {
                "source": "local",
                "path": f"./plugins/{plugin_id}",
            },
            "policy": {
                "installation": "AVAILABLE",
                "authentication": "ON_INSTALL",
            },
            "category": "Coding",
        }
    ],
}

with open(marketplace_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")
PY
fi

printf '%s\n' \
	"Installed Codex plugin into ${PLUGIN_ROOT}" \
	"Updated marketplace at ${MARKETPLACE}" \
	"Restart Codex, open /plugins, choose this repo marketplace, and install ${PLUGIN_ID}."
