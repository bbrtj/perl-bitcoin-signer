package Signer::Role::ReadsScripts;

use v5.40;

use Mooish::Base -role;
use List::Util qw(max);
use Signer::ClientScripts;
use Bitcoin::Crypto qw(btc_utxo);
use Bitcoin::Crypto::Util qw(to_format);

requires qw(
	load_utxos
	extpub_segwit
	extpub_taproot
);

has param 'client_scripts' => (
	isa => InstanceOf ['Signer::ClientScripts'],
	default => sub { Signer::ClientScripts->new },
);

sub get_address ($self, $index, $type, $change)
{
	my $extpub = "extpub_$type";

	return $self->$extpub->derive_key_bip44(
		get_from_account => true,
		change => $change ? 1 : 0,
		index => $index
	)->get_basic_key->get_address;
}

sub get_last_script_args ($self)
{
	my $head = $self->client_scripts->head;
	die 'no client scripts detected!' unless defined $head;

	my $max_address = max
		$head->{state}{address}->segwit,
		$head->{state}{address}->taproot,
		$head->{state}{address}->segwit,
		$head->{state}{address}->taproot
		;

	my %args = (
		fee_rate => $head->{tx}{fee_rate} // 1,
		($head->{tx}{change} ? (change => 1) : ()),
		address_search_range => $max_address + 20,
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
			$address = $self->get_address(
				$head->{state}{address}->increment($output->{type}),
				$output->{type},
				false,
			);

			push $args{self_outputs}->@*, $output_index;
		}
		elsif (fc $address eq fc 'new_change') {
			die 'change output must be set to change value' unless $is_change;
			$address = $self->get_address(
				$head->{state}{change}->increment($output->{type}),
				$output->{type},
				true,
			);

			push $args{self_outputs}->@*, $output_index;
		}
		elsif ($output->{check}) {
			push $args{self_outputs}->@*, $output_index;
		}

		if ($is_change) {
			die 'change set twice' if $args{change};
			$args{change} = $address;
			next;
		}

		my $nulldata = $address =~ s/^nulldata://;
		my %params = (
			locking_script => [($nulldata ? 'NULLDATA' : 'address') => $address],
			value => '' . $value,
		);

		$sum -= $value;
		push $args{outputs}->@*, \%params;
	}

	die "value exceeding inputs (sums to $sum)" if $sum < 0;

	return \%args;
}

