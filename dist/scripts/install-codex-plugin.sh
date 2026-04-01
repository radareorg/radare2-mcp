#!/bin/sh
set -eu

PLUGIN_ID="r2mcp"
SOURCE_DIR="dist/codex-plugin"
REPO_PLUGIN_ROOT="plugins/${PLUGIN_ID}"
REPO_MARKETPLACE=".agents/plugins/marketplace.json"
USER_PLUGIN_ROOT="${HOME}/.codex/plugins/${PLUGIN_ID}"
USER_MARKETPLACE="${HOME}/.agents/plugins/marketplace.json"

install_plugin_copy() {
	dst="$1"
	rm -rf "${dst}"
	mkdir -p "$(dirname "${dst}")"
	cp -R "${SOURCE_DIR}" "${dst}"
}

update_marketplace() {
	marketplace="$1"
	display_name="$2"
	plugin_path="$3"

	mkdir -p "$(dirname "${marketplace}")"
	if [ -f "${marketplace}" ]; then
		perl -MJSON::PP -0pi -e '
			my ($plugin, $display_name, $plugin_path) = @ARGV;
			my $entry = {
				name => $plugin,
				source => {
					source => "local",
					path => $plugin_path,
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
			$payload->{interface}{displayName} = $display_name
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
		' "${PLUGIN_ID}" "${display_name}" "${plugin_path}" "${marketplace}"
	else
		python3 - "${marketplace}" "${PLUGIN_ID}" "${display_name}" "${plugin_path}" <<'PY'
import json
import sys

marketplace_path = sys.argv[1]
plugin_id = sys.argv[2]
display_name = sys.argv[3]
plugin_path = sys.argv[4]

payload = {
    "name": "local-repo",
    "interface": {
        "displayName": display_name,
    },
    "plugins": [
        {
            "name": plugin_id,
            "source": {
                "source": "local",
                "path": plugin_path,
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
}

install_plugin_copy "${REPO_PLUGIN_ROOT}"
install_plugin_copy "${USER_PLUGIN_ROOT}"

update_marketplace "${REPO_MARKETPLACE}" "Local Repo Plugins" "./plugins/${PLUGIN_ID}"
update_marketplace "${USER_MARKETPLACE}" "Personal Plugins" "./.codex/plugins/${PLUGIN_ID}"

printf '%s\n' \
	"Installed Codex plugin into ${REPO_PLUGIN_ROOT}" \
	"Installed Codex plugin into ${USER_PLUGIN_ROOT}" \
	"Updated marketplace at ${REPO_MARKETPLACE}" \
	"Updated marketplace at ${USER_MARKETPLACE}" \
	"Restart Codex, open /plugins, and install ${PLUGIN_ID} from either marketplace."
