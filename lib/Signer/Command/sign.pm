package Signer::Command::sign;

use v5.38;

use Moo;
use Mooish::AttributeBuilder;
use Bitcoin::Crypto qw(btc_transaction btc_extpub btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);
use Bitcoin::Crypto::Network;
use Signer::ClientScripts;
use Signer::Util;
use Mojo::UserAgent;

extends 'Mojolicious::Command';

has field 'description' => (
	default => sub {
		'Run signer client on hot device',
	},
);

has field 'usage' => (
	default => sub ($self) {
		$self->extract_usage,
	},
);

has field 'extpub' => (
	lazy => sub ($self) {
		return btc_extpub->from_serialized([base58 => $self->signer_config->{zpub}]);
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
);

sub get_address ($self, $change, $index)
{
	return $self->extpub->derive_key_bip44(
		change => $change ? 1 : 0,
		index => $index
	)->get_basic_key->get_address;
}

sub load_utxos ($self, $txid_hex)
{
	state $loaded = {};
	return if $loaded->{$txid_hex};

	my $ua = Mojo::UserAgent->new;
	my $http_tx = $ua->get($self->mempool_api . "/$txid_hex/hex");

	my $res = $http_tx->result;
	die 'Got mempool HTTP error: ' . $res->message if $res->is_error;

	btc_utxo->extract([hex => $res->body]);
	$loaded->{$txid_hex} = !!1;

	return;
}

sub post_transaction ($self, $tx)
{
	my $ua = Mojo::UserAgent->new;
	my $http_tx = $ua->post($self->mempool_api, to_format [hex => $tx->to_serialized]);

	my $res = $http_tx->result;
	die 'Got mempool HTTP error: ' . $res->message if $res->is_error;

	return $res->body;
}

sub get_last_script_args ($self)
{
	my $scripts = Signer::ClientScripts->new;
	my $head = $scripts->head;
	die 'no client scripts detected!' unless defined $head;

	my %args = (
		fee_rate => $head->{tx}{fee_rate} // 1,
		($head->{tx}{change} ? (change => ) : ()),
		change_search_to => $head->{state}{change} + 20,
		address_search_to => $head->{state}{address} + 20,
		inputs => [],
		outputs => [],
		self_outputs => [],
	);

	my $sum = 0;
	foreach my $input ($head->{tx}{inputs}->@*) {
		my ($txid, $ind) = $input->{utxo}->@*;
		$self->load_utxos($txid);

		my $utxo = btc_utxo->get([hex => $txid], $ind);
		my %params = (
			txid => [hex => $txid],
			output_index => $ind,
			output => {
				locking_script => [hex => to_format [hex => $utxo->output->locking_script->to_serialized]],
				value => '' . $utxo->output->value,
			},
		);

		$sum += $utxo->output->value;
		push $args{inputs}->@*, \%params;
	}

	foreach my $output_index (keys $head->{tx}{outputs}->@*) {
		my $output = $head->{tx}{outputs}[$output_index];
		die 'outputs after new_change output'
			if $args{change};

		my $value = $output->{value};
		my $is_change = fc $value eq fc 'change';

		my $address = $output->{address};
		if (fc $address eq fc 'new_address') {
			$address = $self->get_address(!!0, $head->{state}{address}++);
			push $args{self_outputs}->@*, $output_index;
		}
		elsif (fc $address eq fc 'new_change') {
			die 'change set twice' if $args{change};
			die 'change output must be set to change value' unless $is_change;
			$address = $self->get_address(!!1, $head->{state}{change}++);
			push $args{self_outputs}->@*, $output_index;
		}
		elsif ($output->{check}) {
			push $args{self_outputs}->@*, $output_index;
		}

		if ($is_change) {
			$args{change} = $address;
			next;
		}

		my %params = (
			locking_script => [Signer::Util::get_address_type($address), $address],
			value => '' . $value,
		);

		$sum -= $value;
		push $args{outputs}->@*, \%params;
	}

	die "value exceeding inputs (sums to $sum)" if $sum < 0;

	return \%args;
}

sub run ($self, @args)
{
	my $params = $self->get_last_script_args;
	my $result = $self->do_post('/sign',
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

