#!/bin/sh
set -eu

PLUGIN_ID="r2mcp"
PLUGIN_ROOT="plugins/${PLUGIN_ID}"
MARKETPLACE=".agents/plugins/marketplace.json"

rm -rf "${PLUGIN_ROOT}"

if [ -f "${MARKETPLACE}" ]; then
	perl -MJSON::PP -0pi -e '
		my $plugin = "r2mcp";
		my $payload = eval { decode_json($_) };
		die "invalid marketplace json\n" if !$payload || ref($payload) ne "HASH";
		$payload->{plugins} = [] if ref($payload->{plugins}) ne "ARRAY";
		$payload->{plugins} = [
			grep {
				ref($_) ne "HASH" || (($_->{name} // "") ne $plugin)
			} @{$payload->{plugins}}
		];
		$_ = JSON::PP->new->pretty->canonical->encode($payload);
	' "${MARKETPLACE}"
fi

printf '%s\n' \
	"Removed Codex plugin from ${PLUGIN_ROOT}" \
	"Removed ${PLUGIN_ID} marketplace entry from ${MARKETPLACE}" \
	"Restart Codex to refresh the plugin list."
