package Signer::Command::sign;

use v5.40;

use Mooish::Base;
use Bitcoin::Crypto qw(btc_transaction btc_extpub btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;
use Mojo::UserAgent;

extends 'Mojolicious::Command';

has field 'description' => (
	default => sub {
		'Run signer client on hot device';
	},
);

has field 'usage' => (
	default => sub ($self) {
		$self->extract_usage;
	},
);

has field 'extpub_segwit' => (
	lazy => sub ($self) {
		return btc_extpub->from_serialized([base58 => $self->signer_config->{extpub_segwit}]);
	},
);

has field 'extpub_taproot' => (
	lazy => sub ($self) {
		return btc_extpub->from_serialized([base58 => $self->signer_config->{extpub_taproot}]);
	},
);

has field 'mempool_api' => (
	lazy => sub ($self) {
		my $network = Bitcoin::Crypto::Network->get->id;
		if ($network eq 'bitcoin') {
			return 'https://mempool.space/api/tx';
		}
		elsif ($network eq 'bitcoin_testnet') {
			return 'https://mempool.space/testnet/api/tx';
		}
		else {
			die "cannot get mempool API link for network $network";
		}
	}
);

with qw(
	Signer::Role::HasConfig
	Signer::Role::ReadsPasswords
	Signer::Role::QueriesAPI
	Signer::Role::ReadsScripts
);

sub load_utxos ($self, $txid_hex)
{
	state $loaded = {};
	return if $loaded->{$txid_hex};

	my $ua = Mojo::UserAgent->new;
	my $http_tx = $ua->get($self->mempool_api . "/$txid_hex/hex");

	my $res = $http_tx->result;
	die 'Got mempool HTTP error: ' . $res->message . "\n" . $res->content->asset->slurp if $res->is_error;

	btc_utxo->extract([hex => $res->body]);
	$loaded->{$txid_hex} = !!1;

	return;
}

sub post_transaction ($self, $tx)
{
	my $ua = Mojo::UserAgent->new;
	my $http_tx = $ua->post($self->mempool_api, to_format [hex => $tx->to_serialized]);

	my $res = $http_tx->result;
	die 'Got mempool HTTP error: ' . $res->message . "\n" . $res->content->asset->slurp if $res->is_error;

	return $res->body;
}

sub run ($self, @args)
{
	my $params = $self->get_last_script_args;
	my $result = $self->do_post(
		'/sign',
		signer_password => $self->read_password('system'),
		password => $self->read_password('wallet'),
		$params->%*,
	);

	my $tx = btc_transaction->from_serialized([hex => $result]);
	$tx->verify;
	say $tx->dump;
	say "checked outputs: <$params->{self_outputs}->@*>"
		if $params->{self_outputs}->@*;

	say $result;
	print 'broadcast this transaction? Type YES to proceed: ';
	my $answer = readline STDIN;

	chomp $answer;
	if ($answer eq 'YES') {
		say 'txid: ' . $self->post_transaction($tx);
	}
}

__END__

=head1 SYNOPSIS

	Usage: APPLICATION sign [CLIENT_SCRIPT]

	Needs signer_host and signer_port configured in signer.yml.

