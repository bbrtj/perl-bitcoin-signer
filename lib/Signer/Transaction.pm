package Signer::Transaction;

use v5.38;
use Moo;
use Mooish::AttributeBuilder;
use Types::Common qw(InstanceOf HashRef);
use Bitcoin::Crypto qw(btc_transaction);

use Signer::Util;
use Signer::Input::Transaction;

has param 'parent' => (
	isa => InstanceOf ['Signer'],
	handles => {
		config => 'signer_config',
	},
);

has param 'input' => (
	coerce => (InstanceOf ['Signer::Input::Transaction'])
		->plus_coercions(HashRef, q{ Signer::Input::Transaction->new($_) }),
);

with qw(Signer::Role::HasMasterKey);

sub get_excess_sats ($self, $tx, $fee_rate)
{
	my $size = $tx->virtual_size;
	my $current_fee_rate = $tx->fee_rate;
	my $excess_sats = $size * ($current_fee_rate - $fee_rate);

	# gets bigint from bigfloat
	return $excess_sats->as_number;
}

sub get_change_key ($self)
{
	my $change = $self->input->change;
	die 'no change address specified'
		unless defined $change;

	# dies if not found
	$self->find_key($change, change => 1);
	return $change;
}

sub find_key ($self, $address, %opts)
{
	my $type = Signer::Util::get_address_type($address);
	my %purpose_map = (
		P2PKH => 44,
		P2SH => 49,
		P2WPKH => 84,
	);
	my $purpose = $purpose_map{$type};

	my $input = $self->input;
	my @config = (
		($opts{change} ? () : {
			change => 0,
			from => $input->address_search_from,
			to => $input->address_search_to,
		}),
		{
			change => 1,
			from => $input->change_search_from,
			to => $input->change_search_to,
		},
	);

	my $acc_key = $self->master_key($purpose);
	for my $conf (@config) {
		foreach my $ind ($conf->{from} .. $conf->{to}) {
			my $key = $acc_key->derive_key_bip44(
				get_from_account => 1,
				change => $conf->{change},
				index => $ind,
			)->get_basic_key;

			return $key
				if $key->get_public_key->get_address eq $address;
		}
	}

	die "address $address not found in this master key";
}

sub get_tx ($self)
{
	my $input = $self->input;

	my $tx = btc_transaction->new;
	my @keys;
	my sub sign {
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

		# presign to get size and adjust the fee
		sign;

		my $excess_fee = $self->get_excess_sats($tx, $input->fee_rate);
		if ($excess_fee > int($tx->virtual_size)) {
			# add change address, but keep in mind it will make the
			# transaction slightly bigger, so only do it if excess sats are
			# more than transaction virtual size
			my $change = $self->input->change;
			$tx->add_output(
				locking_script => [Signer::Util::get_address_type($change), $change],
				value => 0,
			);

			my $output = $tx->outputs->[-1];
			my $output_size = length $output->to_serialized;

			# reduce value by output size times fee rate
			$output->set_value($excess_fee - $output_size * $input->fee_rate);
		}
	}

	# final signing
	sign;

	# final checks
	my $fee_diff = $tx->fee_rate - $input->fee_rate;
	die "fee rate vastly differs from desired fee rate ($fee_diff)"
		if abs($fee_diff) > 1;

	foreach my $output_index ($input->self_outputs->@*) {
		die "no output $output_index"
			unless $tx->outputs->[$output_index];
		# will die if the address is not found in this master key
		$self->find_key($tx->outputs->[$output_index]->locking_script->get_address);
	}

	return $tx;
}

