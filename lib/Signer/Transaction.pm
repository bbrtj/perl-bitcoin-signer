package Signer::Transaction;

use v5.40;
use Mooish::Base;
use Bitcoin::Crypto qw(btc_transaction);
use Bitcoin::Crypto::Util qw(get_address_type);
use Bitcoin::Crypto::Constants qw(:bip44);

use Signer::Input::Transaction;

has param 'input' => (
	coerce => (InstanceOf ['Signer::Input::Transaction'])
		->plus_coercions(HashRef, q{ Signer::Input::Transaction->new($_) }),
);

has field '_key_cache' => (
	isa => HashRef,
	default => sub { {} },
);

with qw(
	Signer::Role::HasConfig
	Signer::Role::HasMasterKey
);

sub get_excess_sats ($self, $tx, $fee_rate)
{
	my $size = $tx->virtual_size;
	my $current_fee_rate = $tx->fee_rate;
	my $excess_sats = $size * ($current_fee_rate - $fee_rate);

	return int $excess_sats;
}

sub get_change_key ($self)
{
	my $change = $self->input->change;
	die 'no change address specified'
		unless defined $change;

	# dies if not found
	$self->find_key($change, change => true);
	return $change;
}

sub _get_key ($self, $purpose, $change, $index)
{
	my $cache = $self->_key_cache;
	my $acc_key = $cache->{$purpose}{acc_key} //=
		$self->master_key($purpose);

	return $cache->{$purpose}{$change}[$index] //= do {
		my $key = $acc_key->derive_key_bip44(
			get_from_account => true,
			change => $change,
			index => $index,
		)->get_basic_key;

		[$key, $key->get_public_key->get_address];
	};
}

sub find_key ($self, $address, %opts)
{
	my $type = get_address_type($address);
	my %purpose_map = (
		P2PKH => BIP44_PURPOSE,
		P2SH => BIP44_COMPAT_PURPOSE,
		P2WPKH => BIP44_SEGWIT_PURPOSE,
		P2TR => BIP44_TAPROOT_PURPOSE,
	);
	my $purpose = $purpose_map{$type};

	for my $change (0, 1) {
		next if $opts{change} && !$change;

		foreach my $ind (0 .. $self->input->address_search_range) {
			my $key_data = $self->_get_key($purpose, $change, $ind);
			return $key_data->[0]
				if $key_data->[1] eq $address;
		}
	}

	die "address $address not found in this master key";
}

sub get_tx ($self)
{
	my $input = $self->input;

	my $tx = btc_transaction->new;
	my @keys;
	my sub sign
	{
		foreach my $key_ind (keys @keys) {
			my $key = $keys[$key_ind];
			$key->sign_transaction($tx, signing_index => $key_ind);
		}
	}

	foreach my $utxo ($input->inputs->@*) {

		# find input with master_key (either change or normal)
		# need info on last used address
		push @keys, $self->find_key($utxo->output->locking_script->get_address);

		$tx->add_input(utxo => $utxo);
	}

	foreach my $output ($input->outputs->@*) {
		$tx->add_output($output);
	}

	$tx->set_rbf;

	if ($input->change) {
		die 'fee_rate is required if one of the outputs is a change address!'
			unless defined $input->fee_rate;

		# presign to get size and adjust the fee
		sign;

		my $excess_fee = $self->get_excess_sats($tx, $input->fee_rate);
		if ($excess_fee > int($tx->virtual_size)) {

			# add change address, but keep in mind it will make the
			# transaction slightly bigger, so only do it if excess sats are
			# more than transaction virtual size
			$tx->add_output(
				locking_script => [address => $input->change],
				value => 0,
			);

			my $output = $tx->outputs->[-1];
			my $output_size = length $output->to_serialized;

			# reduce value by output size times fee rate
			$output->set_value($excess_fee - int($output_size * $input->fee_rate));
		}
	}

	# final signing
	sign;

	# final checks
	if (defined $input->fee_rate) {
		my $fee_diff = $tx->fee_rate - $input->fee_rate;
		die "fee rate vastly differs from desired fee rate (difference: $fee_diff)"
			if abs($fee_diff) > 1;
	}

	foreach my $output_index ($input->self_outputs->@*) {
		die "no output $output_index"
			unless $tx->outputs->[$output_index];

		# will die if the address is not found in this master key
		$self->find_key($tx->outputs->[$output_index]->locking_script->get_address);
	}

	return $tx;
}

