#!/bin/sh
set -eu

PLUGIN_ID="r2mcp"
REPO_PLUGIN_ROOT="plugins/${PLUGIN_ID}"
REPO_MARKETPLACE=".agents/plugins/marketplace.json"
USER_PLUGIN_ROOT="${HOME}/.codex/plugins/${PLUGIN_ID}"
USER_MARKETPLACE="${HOME}/.agents/plugins/marketplace.json"

remove_marketplace_entry() {
	marketplace="$1"
	if [ -f "${marketplace}" ]; then
		perl -MJSON::PP -0pi -e '
			my ($plugin) = @ARGV;
			my $payload = eval { decode_json($_) };
			die "invalid marketplace json\n" if !$payload || ref($payload) ne "HASH";
			$payload->{plugins} = [] if ref($payload->{plugins}) ne "ARRAY";
			$payload->{plugins} = [
				grep {
					ref($_) ne "HASH" || (($_->{name} // "") ne $plugin)
				} @{$payload->{plugins}}
			];
			$_ = JSON::PP->new->pretty->canonical->encode($payload);
		' "${PLUGIN_ID}" "${marketplace}"
	fi
}

rm -rf "${REPO_PLUGIN_ROOT}"
rm -rf "${USER_PLUGIN_ROOT}"
remove_marketplace_entry "${REPO_MARKETPLACE}"
remove_marketplace_entry "${USER_MARKETPLACE}"

printf '%s\n' \
	"Removed Codex plugin from ${REPO_PLUGIN_ROOT}" \
	"Removed Codex plugin from ${USER_PLUGIN_ROOT}" \
	"Removed ${PLUGIN_ID} marketplace entry from ${REPO_MARKETPLACE}" \
	"Removed ${PLUGIN_ID} marketplace entry from ${USER_MARKETPLACE}" \
	"Restart Codex to refresh the plugin list."
